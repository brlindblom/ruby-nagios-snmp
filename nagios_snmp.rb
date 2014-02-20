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
  attr_accessor :return_code, :perror, :snmp_host, :snmp_community, :snmp_version, :param_file, :identifier

  def initialize(snmp_host, snmp_community, snmp_version, param_file, strict)
    @snmp_host      = snmp_host 
    @snmp_community = snmp_community
    @snmp_version   = snmp_version
    @param_file     = param_file
    @perror         = []
    @return_code    = 0
    @id_list        = {}
    @strict         = strict
    
    return nil if parse_param_file != 0
  end

  def evaluate
    dbgp LOG_INFO, "NagiosSNMP::evaluate(): Bulk getting oids: #{@oid_list.join(", ")}"

    snmp_manager do |manager|
      result = manager.get(@oid_list.map{ |oid| ::SNMP::ObjectId.new(oid) })
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
    @identifier + ": " + @perror.join(", ")
  end

  private
    # This lets us specify this method just once, and we can reference it as snmp_manager elsewhere
    def snmp_manager(&block)
      dbgp LOG_INFO, "::SNMP::Manager.open(:host => #{self.snmp_host}, :community => #{self.snmp_community}, :MibModules => #{@param_map['mibs']}, ...)"
      ::SNMP::Manager.open(:host => self.snmp_host, :community => self.snmp_community, :MibModules => @param_map['mibs'], &block)
    end

    
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
          best_message = get_descriptor_for_oid(oid) + " = " + value.to_s + ": " + map[2].to_s
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
        snmp_manager do |manager|
          id = manager.get_value(search_oid)
        end
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

    # read in our param file and convert it into a nice usable hash, and generate our bulk get oid list
    def parse_param_file
      @oid_list = []
      file = File.open(@param_file, "rb")
      if file.nil?
        $sterr.puts "Error opening parameter file: #{@param_file}"
        return -1
      else
        cfg = file.read
        @param_map = JSON.parse(cfg)
      end
      @identifier = @param_map['identifier']

      # generate our oid list
      oid_base_list = @param_map['oids'].keys.reject{|i| i == 'default'}
      oid_base_list.each { |oid| @oid_list.concat(range_expand(oid)) }
      return 0
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
      snmp_manager do |manager|
        manager.walk(oid) { |result| ids << result.value.to_i }
      end

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
      
      snmp_manager do |manager|
        local_oid_list = filter_oids.map { |id| ::SNMP::ObjectId.new(id) }
        result = manager.get_bulk(0, 1, local_oid_list)
        list = result.varbind_list

        list.each do |i|
          exclude_table.each do |t|
            e_oid = oid_to + "." + i.name[-1].to_s
            eval_code = "exclude_map_oid_list << e_oid if not #{parse_map(t[0], i.value.to_s)}"
            eval eval_code
          end
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

begin
  obj = NagiosSNMP.new(options[:host], options[:community], options[:version], options[:cfg], options[:strict])
rescue Exception => e
  puts "nagios_snmp.rb: #{e.message}"
  exit(STATE_UNKNOWN)
end

dbgp LOG_VERBOSE, obj.oid_list.pretty_inspect.to_s
dbgp LOG_VERBOSE, JSON.pretty_generate(JSON.parse(obj.map.to_json))

if obj.nil?
  $stderr.puts "Error parsing #{ARGV[0]}... Exiting."
  exit(STATE_UNKNOWN)
end

begin
  obj.evaluate
rescue Exception => e
  puts "nagios_snmp.rb: #{e.message}"
  exit(STATE_UNKNOWN)
end

if obj.return_code != 0
  puts obj.error_pretty_print
  exit(obj.return_code)
else
  puts obj.identifier + ": OK"
  exit(0)
end
