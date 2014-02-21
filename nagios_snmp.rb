#!/usr/bin/env ruby

# Maintainer : Brian Lindblom
# Where/When/How : This will be run on the nagios server and can do abitrary SNMP checks
# Description : This script gets various SNMP OIDs and compares retreived values against a map to
#               determine appropriate Nagios return code and output strings
# Return Values : 0/1/2/3 - Return codes for OK, Warning, Critical, and unknown respectively for Nagios.
# Assumptions : ruby-snmp gem is available
# Created 20140213 lindblom

require 'rubygems'
require 'snmp'
require 'pp'
require 'optparse'
require 'json'

STATE_OK        = 0
STATE_WARNING   = 1
STATE_CRITICAL  = 2
STATE_UNKNOWN   = 3

LOG_INFO        = 1
LOG_VERBOSE     = 2
LOG_DEBUG       = 3

$verbose = 0

# Print if debugging is sufficiently enabled
def dbgp(level, *args)
  $stderr.puts *args if level <= $verbose
end 

class NagiosSNMP
  attr_accessor :return_code, :perror, :snmp_host, :snmp_community, :snmp_version, :param_file, :identifier, :snmp_manager

  def initialize(snmp_host, snmp_community, snmp_version, param_file, strict)
    @snmp_host      = snmp_host 
    @snmp_community = snmp_community
    @snmp_version   = snmp_version
    @param_file     = param_file
    @perror         = []
    @return_code    = 0
    @id_list        = {}
    @strict         = strict
    @oid_list = []

    file = File.open(@param_file, "rb")
    if file.nil?
      raise "Error opening parameter file: #{@param_file}"
    else
      cfg = file.read
      @param_map = JSON.parse(cfg)
    end

    @identifier = @param_map['identifier']
    
    @snmp_manager = ::SNMP::Manager.new(:host => @snmp_host, :community => @snmp_community, :MibModules => @param_map['mibs'])

    # generate our oid list
    oid_base_list = @param_map['oids'].keys.reject{|i| i == 'default'}
    oid_base_list.each { |oid| @oid_list.concat(range_expand(oid)) }
  end

  def evaluate
    dbgp LOG_INFO, "NagiosSNMP::evaluate(): Bulk getting oids: #{@oid_list.join(", ")}"

    result = @snmp_manager.get(@oid_list.map{ |oid| ::SNMP::ObjectId.new(oid) })
    items = result.varbind_list

    items.each do |item|
      oid = item.name.join('.')
      if item.value.to_s == "noSuchInstance"
        if @strict
          set_return_code STATE_UNKNOWN
          @perror << "#{oid} couldn't be checked"
        end
        dbgp LOG_INFO, "NagiosSNMP::evaluate(): Tried to get invalid OID #{oid}"
        next
      end
      dbgp LOG_VERBOSE, "NagiosSNMP.evaluate(): checking #{oid}"
      value_map = get_param_for_oid(oid, 'value_map')
      (message, rc) = map_to_value_map(oid, item.value, value_map)
      if rc > STATE_OK
        set_return_code rc
        @perror << message if !message.nil?
      end
    end
  end

  def close
    @snmp_manager.close
  end

  # These are helpers for debugging
  def oid_list
    @oid_list
  end

  def map
    @param_map
  end

  # Prints our error strings from @perror, into a single-line output for Nagios
  def error_pretty_print
    ($verbose > 0 ? @identifier + ": " : nil).to_s + @perror.join(", ")
  end

  private
    def parse_map(map_string, value)
      map_string.gsub("%value", value.to_s)
    end

    # returns the most urgent message and return code based on the oid, value, and value_map
    def map_to_value_map(oid, value, value_map)
      dbgp LOG_DEBUG, "map_to_value_map(#{oid}, #{value.to_s}, #{value_map.to_s})"
      best_code = 0
      best_message = nil
      value_map.each do |map|
        if eval parse_map(map[0], value) and map[1] > best_code
          best_message = get_descriptor_for_oid(oid) + " = " + value.to_s + (map[2].nil? ? nil : " " + map[2].to_s).to_s
          best_code = map[1]
        end
      end
      return [best_message, best_code]
    end

    # return a textual string describing the OID
    def get_descriptor_for_oid(oid)
      dbgp LOG_DEBUG, "get_descriptor_for_oid(#{oid})"
      orig_oid = oid
      id = get_param_for_oid(oid,'id')
      oid_index = oid.split('.').last

      while ! @param_map['oids'].keys.include? oid do
        oid = oid.split('.')
        oid = oid.first(oid.size-1).join('.')
      end

      if id.to_s =~ /^index_oid:.*/
        search_oid = id.split(':')[1] + "." + oid_index.to_s
        dbgp LOG_DEBUG, "Getting descriptor for #{orig_oid} => #{search_oid}"
        id = @snmp_manager.get_value(search_oid)
      elsif id.nil?
        id = oid_index
      end
      dbgp LOG_DEBUG, "get_descriptor_for_oid(#{oid}) => " + @param_map['oids'][oid]['desc'] + " #{id}"
      return @param_map['oids'][oid]['desc'] + " #{id}"
    end

    # update the return_code; return true only if we change
    def set_return_code(val)
      dbgp LOG_DEBUG, "set_return_code(#{val.to_s})"
      if @return_code < val
        @return_code = val
        return true
      else
        return false
      end
    end

    # for a given oid, get the value for a specified set parameter
    def get_param_for_oid(oid, param)
      dbgp LOG_DEBUG, "get_param_for_oid(#{oid}, #{param})"
      while ! @param_map['oids'].keys.include? oid do
        oid = oid.split('.')
        oid = oid.first(oid.size-1).join('.')
      end
          
      if @param_map['oids'][oid][param].nil?
        if !@param_map['oids']['default'].nil?
          return @param_map['oids']['default'][param]
        end
      else
        dbgp LOG_VERBOSE, "get_param_for_oid(): Returning specific value_map"
        return @param_map['oids'][oid][param]
      end
      return nil
    end

    # generate array of index values from oid
    def get_snmp_index_list(oid, oid_to, exclude_table)
      dbgp LOG_DEBUG, "get_snmp_index_list(#{oid}, #{oid_to}, #{exclude_table.to_s})"
      
      ids = []
      @snmp_manager.walk(oid) { |result| ids << result.value.to_i }

      oids = map_with_excluded_index(oid_to, ids, exclude_table)
      dbgp LOG_INFO, "get_snmp_index_list() filtered to #{oids.pretty_inspect.to_s} #{oids.map{|i| get_descriptor_for_oid(i)}.pretty_inspect.to_s}"
      return oids
    end

    # map the id list against the exclude_index filter, to provide only the oid list to bulk get that we want
    # TODO: Fix exclude list
    def map_with_excluded_index(oid_to, ids, exclude_table)
      dbgp LOG_DEBUG, "map_with_excluded_index(#{oid_to}, #{ids.to_s}, #{exclude_table.to_s})"
      exclude_map_oid_list = []
      filter_oids = []

      exclude_oids = exclude_table.map{|i| i[1]}

      exclude_oids.map do |i|
        ids.each do |j|
          filter_oids << i.to_s + "." + j.to_s
        end
      end
      
      local_oid_list = filter_oids.map { |id| ::SNMP::ObjectId.new(id) }
      result = @snmp_manager.get_bulk(0, 1, local_oid_list)
      list = result.varbind_list

      list.each do |i|
        exclude_table.each do |t|
          e_oid = oid_to + "." + i.name[-1].to_s
          eval_code = "exclude_map_oid_list << e_oid if not #{parse_map(t[0], i.value.to_s)}"
          eval eval_code
        end
      end
      return exclude_map_oid_list
    end

    # This generates an oid list based on the oid and the expansion of the associated range
    def range_expand(oid)
      dbgp LOG_DEBUG, "range_expand(#{oid})"
      list = []
      range_def = get_param_for_oid(oid,'range')

      # simple range
      if range_def =~ /^\d+\-\d+$/
        (start,finish) = range_def.split('-')
        (start..finish).each { |i| list << oid + "." + i.to_s }
      elsif range_def =~ /^index_oid:.*/
        list = get_snmp_index_list(range_def.split(':')[1], oid, get_param_for_oid(oid, 'exclude_index_map'))
      elsif range_def =~ /^(\d+\,)+\d+$/
        range_def[:expr].each { |i| list << oid + "." + i.to_s }
      elsif range_def.nil?
        list << oid
      end
      return list
    end
end

# default options
options = {
  :host => "localhost",
  :community => "public",
  :version => 2,
  :strict => false,
  :cfg => nil
}

optparse = OptionParser.new do |opts|
  opts.banner = "Usage: check_snmp_generic.rb [options]"
  opts.on("-v", "--verbose", "Run with extra output turned on") { |v| $verbose += 1 }
  opts.on("-V", "--version [VERSION]", "Specity SNMP version: 1,2,3") { |v| options[:version] = v }
  opts.on("-c", "--community [STRING]", "Specify SNMP community string") { |v| options[:community] = v }
  opts.on("-H", "--host [HOSTNAME]", "Specify SNMP agent host") { |v| options[:host] = v }
  opts.on("-s", "--strict", "If OIDs in a defined range are missing, generate an error") { |v| options[:strict] = true }
  opts.on("-C", "--config [FILE]", "Specify check_snmp_generic configuration file") { |v| options[:cfg] = v }
  opts.on("-h", "--help", "Display this help") do |v|
    puts opts
    exit
  end
end.parse!

dbgp LOG_INFO, "Verbosity: #{$verbose}"
dbgp LOG_INFO, "Command line option hash: #{options.pretty_inspect.to_s}"

if options[:cfg].nil?
  $stderr.puts "Specifying a configuration with -C is mandatory!"
  exit(-1)
end

if $verbose == 0
  begin
    nagios_obj = NagiosSNMP.new(options[:host], options[:community], options[:version], options[:cfg], options[:strict])
  rescue Exception => e
    puts "1 nagios_snmp.rb: #{e.message}"
    exit(STATE_UNKNOWN)
  end
else
  nagios_obj = NagiosSNMP.new(options[:host], options[:community], options[:version], options[:cfg], options[:strict])
end

dbgp LOG_VERBOSE, nagios_obj.oid_list.pretty_inspect.to_s
dbgp LOG_VERBOSE, JSON.pretty_generate(JSON.parse(nagios_obj.map.to_json))

if nagios_obj.nil?
  $stderr.puts "Error parsing #{options[:cfg]}... Exiting."
  exit(STATE_UNKNOWN)
end

# if we're verbose, let's get the full stack trace
if $verbose == 0
  begin
    nagios_obj.evaluate
  rescue Exception => e
    puts "2 nagios_snmp.rb: #{e.message}"
    nagios_obj.close
    exit(STATE_UNKNOWN)
  end
else
  nagios_obj.evaluate
end


if nagios_obj.return_code != 0
  puts(nagios_obj.error_pretty_print)
  rc = nagios_obj.return_code
  nagios_obj.close
  exit(rc)
else
  puts(($verbose > 0 ? nagios_obj.identifier + ": " : nil).to_s + "OK")
  nagios_obj.close
  exit(0)
end
