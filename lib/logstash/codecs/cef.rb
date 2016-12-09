# encoding: utf-8
require "logstash/util/buftok"
require "logstash/codecs/base"
require "json"

# Implementation of a Logstash codec for the ArcSight Common Event Format (CEF)
# Based on Revision 20 of Implementing ArcSight CEF, dated from June 05, 2013
# https://protect724.hp.com/servlet/JiveServlet/downloadBody/1072-102-6-4697/CommonEventFormat.pdf
#
# If this codec receives a payload from an input that is not a valid CEF message, then it will
# produce an event with the payload as the 'message' field and a '_cefparsefailure' tag.
class LogStash::Codecs::CEF < LogStash::Codecs::Base
  config_name "cef"

  # Device vendor field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :vendor, :validate => :string, :default => "Elasticsearch"

  # Device product field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :product, :validate => :string, :default => "Logstash"

  # Device version field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :version, :validate => :string, :default => "1.0"

  # Signature ID field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :signature, :validate => :string, :default => "Logstash"

  # Name field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  config :name, :validate => :string, :default => "Logstash"

  # Deprecated severity field for CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #
  # This field is used only if :severity is unchanged set to the default value.
  #
  # Defined as field of type string to allow sprintf. The value will be validated
  # to be an integer in the range from 0 to 10 (including).
  # All invalid values will be mapped to the default of 6.
  config :sev, :validate => :string, :deprecated => "This setting is being deprecated, use :severity instead."

  # Severity field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #
  # Defined as field of type string to allow sprintf. The value will be validated
  # to be an integer in the range from 0 to 10 (including).
  # All invalid values will be mapped to the default of 6.
  config :severity, :validate => :string, :default => "6"

  # Fields to be included in CEV extension part as key/value pairs
  config :fields, :validate => :array, :default => []

  # Set this flag if you want to have both v1 and v2 fields indexed at the same time. Note that this option will increase
  # the index size and data stored in outputs like Elasticsearch
  # This option is available to ease transition to new schema
  config :deprecated_v1_fields, :validate => :boolean, :deprecated => "This setting is being deprecated"

  # If your input puts a delimiter between each CEF event, you'll want to set
  # this to be that delimiter.
  #
  # For example, with the TCP input, you probably want to put this:
  #
  #     input {
  #       tcp {
  #         codec => cef { delimiter => "\r\n" }
  #         # ...
  #       }
  #     }
  #
  # This setting allows the following character sequences to have special meaning:
  #
  # * `\\r` (backslash "r") - means carriage return (ASCII 0x0D)
  # * `\\n` (backslash "n") - means newline (ASCII 0x0A)
  config :delimiter, :validate => :string

  HEADER_FIELDS = ['cefVersion','deviceVendor','deviceProduct','deviceVersion','deviceEventClassId','name','severity']

  # Translating and flattening the CEF extensions with known field names as documented in the Common Event Format whitepaper
  MAPPINGS = { "act" => "deviceAction", "app" => "applicationProtocol", "c6a1" => "deviceCustomIPv6Address1", "c6a1Label" => "deviceCustomIPv6Address1Label", "c6a2" => "deviceCustomIPv6Address2", "c6a2Label" => "deviceCustomIPv6Address2Label", "c6a3" => "deviceCustomIPv6Address3", "c6a3Label" => "deviceCustomIPv6Address3Label", "c6a4" => "deviceCustomIPv6Address4", "c6a4Label" => "deviceCustomIPv6Address4Label", "cat" => "deviceEventCategory", "cfp1" => "deviceCustomFloatingPoint1", "cfp1Label" => "deviceCustomFloatingPoint1Label", "cfp2" => "deviceCustomFloatingPoint2", "cfp2Label" => "deviceCustomFloatingPoint2", "cfp3" => "deviceCustomFloatingPoint3", "cfp3Label" => "deviceCustomFloatingPoint4Label", "cfp4" => "deviceCustomFloatingPoint4", "cfp4Label" => "deviceCustomFloatingPoint4Label", "cn1" => "deviceCustomNumber1", "cn1Label" => "deviceCustomNumber1Label", "cn2" => "deviceCustomNumber2", "cn2Label" => "deviceCustomNumber2Label", "cn3" => "deviceCustomNumber3", "cn3Label" => "deviceCustomNumber3Label", "cnt" => "baseEventCount", "cs1" => "deviceCustomString1", "cs1Label" => "deviceCustomString1Label", "cs2" => "deviceCustomString2", "cs2Label" => "deviceCustomString2Label", "cs3" => "deviceCustomString3", "cs3Label" => "deviceCustomString3Label", "cs4" => "deviceCustomString4", "cs4Label" => "deviceCustomString4Label", "cs5" => "deviceCustomString5", "cs5Label" => "deviceCustomString5Label", "cs6" => "deviceCustomString6", "cs6Label" => "deviceCustomString6Label", "dhost" => "destinationHostName", "dmac" => "destinationMacAddress", "dntdom" => "destinationNTDomain", "dpid" => "destinationProcessId", "dpriv" => "destinationUserPrivileges", "dproc" => "destinationProcessName", "dpt" => "destinationPort", "dst" => "destinationAddress", "duid" => "destinationUserId", "duser" => "destinationUserName", "dvc" => "deviceAddress", "dvchost" => "deviceHostName", "dvcpid" => "deviceProcessId", "end" => "endTime", "fname" => "fileName", "fsize" => "fileSize", "in" => "bytesIn", "msg" => "message", "out" => "bytesOut", "outcome" => "eventOutcome", "proto" => "transportProtocol", "request" => "requestUrl", "rt" => "deviceReceiptTime", "shost" => "sourceHostName", "smac" => "sourceMacAddress", "sntdom" => "sourceNtDomain", "spid" => "sourceProcessId", "spriv" => "sourceUserPrivileges", "sproc" => "sourceProcessName", "spt" => "sourcePort", "src" => "sourceAddress", "start" => "startTime", "suid" => "sourceUserId", "suser" => "sourceUserName", "ahost" => "agentHost", "art" => "agentReceiptTime", "at" => "agentType", "aid" => "agentId", "_cefVer" => "cefVersion", "agt" => "agentAddress", "av" => "agentVersion", "atz" => "agentTimeZone", "dtz" => "destinationTimeZone", "slong" => "sourceLongitude", "slat" => "sourceLatitude", "dlong" => "destinationLongitude", "dlat" => "destinationLatitude", "catdt" => "categoryDeviceType", "mrt" => "managerReceiptTime" }

  DEPRECATED_HEADER_FIELDS = ['cef_version','cef_vendor','cef_product','cef_device_version','cef_sigid','cef_name','cef_severity']

  public
  def initialize(params={})
    super(params)
    if @delimiter
      # Logstash configuration doesn't have built-in support for escaping,
      # so we implement it here. Feature discussion for escaping is here:
      #   https://github.com/elastic/logstash/issues/1645
      @delimiter = @delimiter.gsub("\\r", "\r").gsub("\\n", "\n")
      @buffer = FileWatch::BufferedTokenizer.new(@delimiter)
    end
  end

  private
  def store_header_field(event,field_name,field_data)
    #Unescape pipes and backslash in header fields
    event.set(field_name,field_data.gsub(/\\\|/, '|').gsub(/\\\\/, '\\')) unless field_data.nil?
  end

  public
  def decode(data, &block)
    if @delimiter
      @buffer.extract(data).each do |line|
        handle(line, &block)
      end
    else
      handle(data, &block)
    end
  end

  def handle(data, &block)
    # Strip any quotations at the start and end, flex connectors seem to send this
    if data[0] == "\""
      data = data[1..-2]
    end
    event = LogStash::Event.new

    # Split by the pipes, pipes in the extension part are perfectly valid and do not need escaping
    # The better solution for the splitting regex would be /(?<!\\(\\\\)*)[\|]/, but this
    # gives an "SyntaxError: (RegexpError) invalid pattern in look-behind" for the variable length look behind.
    # Therefore one edge case is not handled properly: \\| (this should split, but it does not, because the escaped \ is not recognized)
    # TODO: To solve all unescaping cases, regex is not suitable. A little parse should be written.
    split_data = data.split /(?<=[^\\]\\\\)[\|]|(?<!\\)[\|]/

    # To be invoked when config settings is set to TRUE for V1 field names (cef_ext.<fieldname>) the following code might be removed in upcoming Codec revision
    if deprecated_v1_fields
      handle_v1_fields(event, split_data)
    end

    # To be invoked with default config settings to utilise the new field name formatting and flatten out the JSON document
    # Store header fields
    HEADER_FIELDS.each_with_index do |field_name, index|
      store_header_field(event,field_name,split_data[index])
    end
    #Remainder is message
    message = split_data[HEADER_FIELDS.size..-1].join('|')

    # Try and parse out the syslog header if there is one
    if event.get('cefVersion').include? ' '
      split_cef_version= event.get('cefVersion').rpartition(' ')
      event.set('syslog', split_cef_version[0])
      event.set('cefVersion',split_cef_version[2])
    end

    # Get rid of the CEF bit in the version
    event.set('cefVersion', event.get('cefVersion').sub(/^CEF:/, ''))

    # Strip any whitespace from the message
    if not message.nil? and message.include? '='
      message = message.strip

      # If the last KVP has no value, add an empty string, this prevents hash errors below
      if message.end_with?('=')
        message = message + ' ' unless message.end_with?('\=')
      end

      # Insert custom delimiter to separate key-value pairs, to which some values will contain special characters
      # This separator '|^^^' os tested to be unique
      message = message.gsub((/(?:(\s+(\w+\=)))/),'|^^^\2')

      # Appropriately tokenizing the additional fields when ArcSight connectors are sending events using "COMPLETE" mode processing.
      # If these fields are NOT needed, then set the ArcSight processing mode for this destination to "FASTER" or "FASTEST"
      # Refer to ArcSight's SmartConnector user configuration guide
      message = message.gsub((/(\s+(\w+\.[^\s]\w+[^\|\s\.\=]+\=))/),'|^^^\2')
      message = message.split('|^^^')

      # Replaces the '=' with '***' to avoid conflict with strings with HTML content namely key-value pairs where the values contain HTML strings
      # Example : requestUrl = http://<testdomain>:<port>?query=A
      for i in 0..message.length-1
        message[i] = message[i].sub(/\=/, "***")
        message[i] = message[i].gsub(/\\=/, '=').gsub(/\\\\/, '\\')
      end

      message = message.map {|s| k, v = s.split('***'); "#{MAPPINGS[k] || k }=#{v}"}
      message = message.each_with_object({}) do |k|
        key, value = k.split(/\s*=\s*/,2)
        event.set(key, value)
      end
    end

    yield event
  rescue => e
    @logger.error("Failed to decode CEF payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
    yield LogStash::Event.new("message" => data, "tags" => ["_cefparsefailure"])
  end

  public
  def encode(event)
    # "CEF:0|Elasticsearch|Logstash|1.0|Signature|Name|Sev|"

    vendor = sanitize_header_field(event.sprintf(@vendor))
    vendor = self.class.get_config["vendor"][:default] if vendor == ""

    product = sanitize_header_field(event.sprintf(@product))
    product = self.class.get_config["product"][:default] if product == ""

    version = sanitize_header_field(event.sprintf(@version))
    version = self.class.get_config["version"][:default] if version == ""

    signature = sanitize_header_field(event.sprintf(@signature))
    signature = self.class.get_config["signature"][:default] if signature == ""

    name = sanitize_header_field(event.sprintf(@name))
    name = self.class.get_config["name"][:default] if name == ""

    # :sev is deprecated and therefore only considered if :severity equals the default setting or is invalid
    severity = sanitize_severity(event, @severity)
    if severity == self.class.get_config["severity"][:default] && @sev
      # Use deprecated setting sev
      severity = sanitize_severity(event, @sev)
    end

    # Should also probably set the fields sent
    header = ["CEF:0", vendor, product, version, signature, name, severity].join("|")
    values = @fields.map {|fieldname| get_value(fieldname, event)}.compact.join(" ")

    @on_event.call(event, "#{header}|#{values}#{@delimiter}")
  end

  private

  # Escape pipes and backslashes in the header. Equal signs are ok.
  # Newlines are forbidden.
  def sanitize_header_field(value)
    output = ""

    value = value.to_s.gsub(/\r\n/, "\n")

    value.each_char{|c|
      case c
      when "\\", "|"
        output += "\\" + c
      when "\n", "\r"
        output += " "
      else
        output += c
      end
    }

    return output
  end

  # Keys must be made up of a single word, with no spaces
  # must be alphanumeric
  def sanitize_extension_key(value)
    value = value.to_s.gsub(/[^a-zA-Z0-9]/, "")
    return value
  end

  # Escape equal signs in the extensions. Canonicalize newlines.
  # CEF spec leaves it up to us to choose \r or \n for newline.
  # We choose \n as the default.
  def sanitize_extension_val(value)
    output = ""

    value = value.to_s.gsub(/\r\n/, "\n")

    value.each_char{|c|
      case c
      when "\\", "="
        output += "\\" + c
      when "\n", "\r"
        output += "\\n"
      else
        output += c
      end
    }

    return output
  end

  def get_value(fieldname, event)
    val = event.get(fieldname)

    return nil if val.nil?

    case val
    when Array, Hash
      return "#{sanitize_extension_key(fieldname)}=#{sanitize_extension_val(val.to_json)}"
    when LogStash::Timestamp
      return "#{sanitize_extension_key(fieldname)}=#{val.to_s}"
    else
      return "#{sanitize_extension_key(fieldname)}=#{sanitize_extension_val(val)}"
    end
  end

  def sanitize_severity(event, severity)
    severity = sanitize_header_field(event.sprintf(severity)).strip
    severity = self.class.get_config["severity"][:default] unless valid_severity?(severity)
    severity = severity.to_i.to_s
  end

  def valid_severity?(sev)
    f = Float(sev)
    # check if it's an integer or a float with no remainder
    # and if the value is between 0 and 10 (inclusive)
    (f % 1 == 0) && f.between?(0,10)
  rescue TypeError, ArgumentError
    false
  end

  def handle_v1_fields(event, split_data)
    # Store header fields
    DEPRECATED_HEADER_FIELDS.each_with_index do |field_name, index|
      store_header_field(event,field_name,split_data[index])
    end
    #Remainder is message
    message = split_data[DEPRECATED_HEADER_FIELDS.size..-1].join('|')

    # Try and parse out the syslog header if there is one
    if event.get('cef_version').include? ' '
      split_cef_version= event.get('cef_version').rpartition(' ')
      event.set('syslog', split_cef_version[0])
      event.set('cef_version',split_cef_version[2])
    end

    # Get rid of the CEF bit in the version
    event.set('cef_version', event.get('cef_version').sub(/^CEF:/, ''))

    # Strip any whitespace from the message
    if not message.nil? and message.include? '='
      message = message.strip

      # If the last KVP has no value, add an empty string, this prevents hash errors below
      if message.end_with?('=')
        message=message + ' ' unless message.end_with?('\=')
      end

      # Now parse the key value pairs into it
      extensions = {}
      message = message.split(/ ([\w\.]+)=/)
      key, value = message.shift.split('=', 2)
      extensions[key] = value.gsub(/\\=/, '=').gsub(/\\\\/, '\\')
      Hash[*message].each{ |k, v| extensions[k] = v }
      # And save the new has as the extensions
      event.set('cef_ext', extensions)
    end

  end

end
