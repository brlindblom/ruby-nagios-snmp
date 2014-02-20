# nagios_snmp.rb: Highly-generalized SNMP check script for Nagios

I hacked this together after working on a ticket for an existing Nagios check script and realizing 
a recurring pattern: many of the SNMP check scripts are doing the same things, functionally and 
logically, but are expressed differently. I figured, in the long-term, it would be nice to have a 
consistent way of doing this that is flexible.

The intent is to replace as many check_snmp-style scripts as possible so that there is a single, 
maintainable code-base. This will make it easier in the long-run to

1. Add new checks
2. On-board new people who will have to deal with Nagios checks as there will be (mostly) a single way to do things
3. VASTLY reduce the number of snmpget/walk/bulkwalk calls made by the Nagios server
4. Integration with configuration management would be much simpler (rather than just storing a bunch of scripts)

The script, written in Ruby, and using the nice ruby-snmp gem, supports the following arguments:

    $ ./nagios_snmp.rb -h
    Usage: check_snmp_generic.rb [options]
        -v, --verbose                    Run with extra output turned on
        -V, --version [VERSION]          Specity SNMP version: 1,2,3
        -c, --community [STRING]         Specify SNMP community string
        -H, --host [HOSTNAME]            Specify SNMP agent host
        -C, --config [FILE]              Specify check_snmp_generic configuration file
        -h, --help                       Display this help

Here's an example JSON configuration that can be fed into nagios_snmp.rb to check filesystems on snmpd-enabled 
Linux hosts:

    /* This configuration will scan all SNMP-defined disks for used percentage
       and used inode percentage */
    {
      // Textual identifier that will display in Nagios output
      "identifier": "Host disk usage",
    
      // Will display list of sub devices even if status = OK
      "ok_display": true,
    
      // List of OIDs to search with various attributes and filters
      "oids": {
    
        // The default OID is special.  Its attributes apply to all other OIDs unless overrode
        "default": {
    
          // The "id" is used as a textual identifier to identify a problem device.  In this case,
          // we are setting the "default" OID to an SNMP index_oid to derive the "id" from the 
          // value of another OID range
          "id": "index_oid:1.3.6.1.4.1.2021.9.1.2",
    
          // The value map is a table that evaluates the values of each of the checked OIDs, mapping
          // each evaluation to an appropriate return code and information string.  Any Ruby-based
          // conditional statement is valid
          "value_map": [
            [ "%value < 90", 0, "OK" ],
            [ "%value >= 90", 1, "Warning" ],
            [ "%value >= 95", 2, "Critical" ]
          ],
          
          // Each OID will inherit a range.  In this case, we will derive the range from an index OID
          "range": "index_oid:1.3.6.1.4.1.2021.9.1.1",
    
          // There may be OIDs in the range defined that we want to exclude based on specific circumstances.
          // In this case, we are excluding filesystems that we don't want to check
          "exclude_index_map": [
            [ "%q{%value} =~ /(devtmpfs|sysfs|proc|devpts|sunrpc|none|[a-zA-Z0-9\.]+\:.*|loop\d+)/", "1.3.6.1.4.1.2021.9.1.3" ]
          ]
        },
    
        // These are individual OIDs for dskPercent and dskPercentNode to get disk usage and inode usage percentage
        "1.3.6.1.4.1.2021.9.1.9": { "desc": "Disk used percentage" },
        "1.3.6.1.4.1.2021.9.1.10": { "desc": "Disk inode used percentage" }
      }
    }
