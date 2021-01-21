# encoding: utf-8
require "logstash/util/buftok"
require "logstash/util/charset"
require "logstash/codecs/base"
require "json"

# Implementation of a Logstash codec for the ArcSight Common Event Format (CEF)
# Based on Revision 20 of Implementing ArcSight CEF, dated from June 05, 2013
# https://community.saas.hpe.com/dcvta86296/attachments/dcvta86296/connector-documentation/1116/1/CommonEventFormatv23.pdf
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

  # Severity field in CEF header. The new value can include `%{foo}` strings
  # to help you build a new value from other parts of the event.
  #
  # Defined as field of type string to allow sprintf. The value will be validated
  # to be an integer in the range from 0 to 10 (including).
  # All invalid values will be mapped to the default of 6.
  config :severity, :validate => :string, :default => "6"

  # Fields to be included in CEV extension part as key/value pairs
  config :fields, :validate => :array, :default => []
  
  # When encoding to CEF, set this to true to adhere to the specifications and
  # encode using the CEF key name (short name) for the CEF field names.
  # Defaults to false to preserve previous behaviour that was to use the long
  # version of the CEF field names.
  config :reverse_mapping, :validate => :boolean, :default => false

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

  # If raw_data_field is set, during decode of an event an additional field with
  # the provided name is added, which contains the raw data.
  config :raw_data_field, :validate => :string

  config :device, :validate => %w(observer host), :default => 'observer'

  # A CEF Header is a sequence of zero or more:
  #  - backslash-escaped pipes; OR
  #  - backslash-escaped backslashes; OR
  #  - non-pipe characters
  HEADER_PATTERN = /(?:\\\||\\\\|[^|])*?/

  # Cache of a scanner pattern that _captures_ a HEADER followed by an unescaped pipe
  HEADER_SCANNER = /(#{HEADER_PATTERN})#{Regexp.quote('|')}/

  # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped pipe, _capturing_ the escaped character
  HEADER_ESCAPE_CAPTURE = /\\([\\|])/

  # Cache of a gsub pattern that matches a backslash-escaped backslash or backslash-escaped equals, _capturing_ the escaped character
  EXTENSION_VALUE_ESCAPE_CAPTURE = /\\([\\=])/

  # While the original CEF spec calls out that extension keys must be alphanumeric and must not contain spaces,
  # in practice many "CEF" producers like the Arcsight smart connector produce non-legal keys including underscores,
  # commas, periods, and square-bracketed index offsets.
  #
  # To support this, we look for a specific sequence of characters that are followed by an equals sign. This pattern
  # will correctly identify all strictly-legal keys, and will also match those that include a dot-joined "subkeys" and
  # square-bracketed array indexing
  #
  # That sequence must begin with one or more `\w` (word: alphanumeric + underscore), which _optionally_ may be followed
  # by one or more "subkey" sequences and an optional square-bracketed index.
  #
  # To be understood by this implementation, a "subkey" sequence must consist of a literal dot (`.`) followed by one or
  # more characters that do not convey semantic meaning within CEF (e.g., literal-dot (`.`), literal-equals (`=`),
  # whitespace (`\s`), literal-pipe (`|`), literal-backslash ('\'), or literal-square brackets (`[` or `]`)).
  EXTENSION_KEY_PATTERN = /(?:\w+(?:\.[^\.=\s\|\\\[\]]+)*(?:\[[0-9]+\])?(?==))/

  # Some CEF extension keys seen in the wild use an undocumented array-like syntax that may not be compatible with
  # the Event API's strict-mode FieldReference parser (e.g., `fieldname[0]`).
  # Cache of a `String#sub` pattern matching array-like syntax and capturing both the base field name and the
  # array-indexing portion so we can convert to a valid FieldReference (e.g., `[fieldname][0]`).
  EXTENSION_KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/ # '[\1]\2'

  # In extensions, spaces may be included in an extension value without any escaping,
  # so an extension value is a sequence of zero or more:
  # - non-whitespace character; OR
  # - runs of whitespace that are NOT followed by something that looks like a key-equals sequence
  EXTENSION_VALUE_PATTERN = /(?:\S|\s++(?!#{EXTENSION_KEY_PATTERN}=))*/

  # Cache of a scanner pattern that _captures_ extension field key/value pairs
  EXTENSION_KEY_VALUE_SCANNER = /(#{EXTENSION_KEY_PATTERN})=(#{EXTENSION_VALUE_PATTERN})\s*/

  ##
  # @see CEF#sanitize_header_field
  HEADER_FIELD_SANITIZER_MAPPING = {
    "\\" => "\\\\",
    "|"  => "\\|",
    "\n" => " ",
    "\r" => " ",
  }
  HEADER_FIELD_SANITIZER_PATTERN = Regexp.union(HEADER_FIELD_SANITIZER_MAPPING.keys)
  private_constant :HEADER_FIELD_SANITIZER_MAPPING, :HEADER_FIELD_SANITIZER_PATTERN

  ##
  # @see CEF#sanitize_extension_val
  EXTENSION_VALUE_SANITIZER_MAPPING = {
    "\\" => "\\\\",
    "="  => "\\=",
    "\n" => "\\n",
    "\r" => "\\n",
  }
  EXTENSION_VALUE_SANITIZER_PATTERN = Regexp.union(EXTENSION_VALUE_SANITIZER_MAPPING.keys)
  private_constant :EXTENSION_VALUE_SANITIZER_MAPPING, :EXTENSION_VALUE_SANITIZER_PATTERN

  CEF_PREFIX = 'CEF:'.freeze

  public
  def initialize(params={})
    super(params)

    # CEF input MUST be UTF-8, per the CEF White Paper that serves as the format's specification:
    # https://web.archive.org/web/20160422182529/https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger

    if @delimiter
      # Logstash configuration doesn't have built-in support for escaping,
      # so we implement it here. Feature discussion for escaping is here:
      #   https://github.com/elastic/logstash/issues/1645
      @delimiter = @delimiter.gsub("\\r", "\r").gsub("\\n", "\n")
      @buffer = FileWatch::BufferedTokenizer.new(@delimiter)
    end

    setup_header_fields!
    setup_mappings!
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
    event = LogStash::Event.new
    event.set(raw_data_field, data) unless raw_data_field.nil?

    @utf8_charset.convert(data)

    # Several of the many operations in the rest of this method will fail when they encounter UTF8-tagged strings
    # that contain invalid byte sequences; fail early to avoid wasted work.
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Strip any quotations at the start and end, flex connectors seem to send this
    if data[0] == "\""
      data = data[1..-2]
    end

    # Use a scanning parser to capture the HEADER_FIELDS
    unprocessed_data = data
    @header_fields.each do |field_name|
      match_data = HEADER_SCANNER.match(unprocessed_data)
      break if match_data.nil? # missing fields

      escaped_field_value = match_data[1]
      next if escaped_field_value.nil?

      # process legal header escape sequences
      unescaped_field_value = escaped_field_value.gsub(HEADER_ESCAPE_CAPTURE, '\1')

      event.set(field_name, unescaped_field_value)
      unprocessed_data = match_data.post_match
    end

    #Remainder is message
    message = unprocessed_data

    # Try and parse out the syslog header if there is one
    if (cef_version = event.get('cefVersion')).include?(' ')
      split_cef_version = cef_version.rpartition(' ')
      event.set('syslog', split_cef_version[0])
      event.set('cefVersion', split_cef_version[2])
    end

    # Get rid of the CEF bit in the version
    event.set('cefVersion', delete_cef_prefix(event.get('cefVersion')))

    # Use a scanning parser to capture the Extension Key/Value Pairs
    if message && message.include?('=')
      message = message.strip

      message.scan(EXTENSION_KEY_VALUE_SCANNER) do |extension_field_key, raw_extension_field_value|
        # expand abbreviated extension field keys
        extension_field_key = @mapping.fetch(extension_field_key, extension_field_key)

        # convert extension field name to strict legal field_reference, fixing field names with ambiguous array-like syntax
        extension_field_key = extension_field_key.sub(EXTENSION_KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')

        # process legal extension field value escapes
        extension_field_value = raw_extension_field_value.gsub(EXTENSION_VALUE_ESCAPE_CAPTURE, '\1')

        event.set(extension_field_key, extension_field_value)
      end
    end

    yield event
  rescue => e
    @logger.error("Failed to decode CEF payload. Generating failure event with payload in message field.",
                  :exception => e.class, :message => e.message, :backtrace => e.backtrace, :data => data)
    yield LogStash::Event.new("message" => data, "tags" => ["_cefparsefailure"])
  end

  public
  def encode(event)
    # "CEF:0|Elasticsearch|Logstash|1.0|Signature|Name|Sev|"

    vendor = sanitize_header_field(event.sprintf(@vendor))
    vendor = self.class.get_config["vendor"][:default] if vendor.empty?

    product = sanitize_header_field(event.sprintf(@product))
    product = self.class.get_config["product"][:default] if product.empty?

    version = sanitize_header_field(event.sprintf(@version))
    version = self.class.get_config["version"][:default] if version.empty?

    signature = sanitize_header_field(event.sprintf(@signature))
    signature = self.class.get_config["signature"][:default] if signature.empty?

    name = sanitize_header_field(event.sprintf(@name))
    name = self.class.get_config["name"][:default] if name.empty?

    severity = sanitize_severity(event, @severity)

    # Should also probably set the fields sent
    header = ["CEF:0", vendor, product, version, signature, name, severity].join("|")
    values = @fields.map { |fieldname| get_value(fieldname, event) }.compact.join(" ")

    @on_event.call(event, "#{header}|#{values}#{@delimiter}")
  end

  private

  # Escape pipes and backslashes in the header. Equal signs are ok.
  # Newlines are forbidden.
  def sanitize_header_field(value)
    value.to_s
         .gsub("\r\n", "\n")
         .gsub(HEADER_FIELD_SANITIZER_PATTERN, HEADER_FIELD_SANITIZER_MAPPING)
  end

  # Keys must be made up of a single word, with no spaces
  # must be alphanumeric
  def sanitize_extension_key(value)
    value.to_s
         .gsub(/[^a-zA-Z0-9]/, "")
  end

  # Escape equal signs in the extensions. Canonicalize newlines.
  # CEF spec leaves it up to us to choose \r or \n for newline.
  # We choose \n as the default.
  def sanitize_extension_val(value)
    value.to_s
         .gsub("\r\n", "\n")
         .gsub(EXTENSION_VALUE_SANITIZER_PATTERN, EXTENSION_VALUE_SANITIZER_MAPPING)
  end

  def get_value(fieldname, event)
    val = event.get(fieldname)

    return nil if val.nil?

    key = sanitize_extension_key(fieldname)
    
    if @reverse_mapping
      key = @mapping_inverted[key] || key
    end
    
    case val
    when Array, Hash
      return "#{key}=#{sanitize_extension_val(val.to_json)}"
    when LogStash::Timestamp
      return "#{key}=#{val.to_s}"
    else
      return "#{key}=#{sanitize_extension_val(val)}"
    end
  end

  def sanitize_severity(event, severity)
    severity = sanitize_header_field(event.sprintf(severity)).strip
    severity = self.class.get_config["severity"][:default] unless valid_severity?(severity)
    severity.to_i.to_s
  end

  def valid_severity?(sev)
    f = Float(sev)
    # check if it's an integer or a float with no remainder
    # and if the value is between 0 and 10 (inclusive)
    (f % 1 == 0) && f.between?(0,10)
  rescue TypeError, ArgumentError
    false
  end

  # setup `@header_fields`, an ordered array of field names
  def setup_header_fields!
    return if @header_fields

    @header_fields = %w[
      cefVersion
      deviceVendor
      deviceProduct
      deviceVersion
      deviceEventClassId
      name
      severity
    ].freeze
  end

  # Translating and flattening the CEF extensions with known field names as documented in the Common Event Format whitepaper
  # Reverse mapping of CEF full field names to CEF extensions field names for encoding into a CEF event for output.
  def setup_mappings!
    return if @mapping

    # TODO: Once using ECSCompatibilitySupport v1.1, we get ecs_select for free
    chooser = Chooser.new([:disabled, :v1])
    ecs_select = chooser.choose(ecs_compatibility, 'ecs_compatibility mode', LogStash::ConfigurationError)

    @mapping = {
      "act"       => ecs_select[disabled: "deviceAction",                    v1: "[event][action]"],
      "app"       => ecs_select[disabled: "applicationProtocol",             v1: "[network][protocol]"],
      "c6a1"      => ecs_select[disabled: "deviceCustomIPv6Address1",        v1: "[cef][device_custom_ipv6_address_1][value]"],
      "c6a1Label" => ecs_select[disabled: "deviceCustomIPv6Address1Label",   v1: "[cef][device_custom_ipv6_address_1][label]"],
      "c6a2"      => ecs_select[disabled: "deviceCustomIPv6Address2",        v1: "[cef][device_custom_ipv6_address_2][value]"],
      "c6a2Label" => ecs_select[disabled: "deviceCustomIPv6Address2Label",   v1: "[cef][device_custom_ipv6_address_2][label]"],
      "c6a3"      => ecs_select[disabled: "deviceCustomIPv6Address3",        v1: "[cef][device_custom_ipv6_address_3][value]"],
      "c6a3Label" => ecs_select[disabled: "deviceCustomIPv6Address3Label",   v1: "[cef][device_custom_ipv6_address_3][label]"],
      "c6a4"      => ecs_select[disabled: "deviceCustomIPv6Address4",        v1: "[cef][device_custom_ipv6_address_4][value]"],
      "c6a4Label" => ecs_select[disabled: "deviceCustomIPv6Address4Label",   v1: "[cef][device_custom_ipv6_address_4][label]"],
      "cat"       => ecs_select[disabled: "deviceEventCategory",             v1: "[cef][category]"],
      "cfp1"      => ecs_select[disabled: "deviceCustomFloatingPoint1",      v1: "[cef][device_custom_floating_point_1][value]"],
      "cfp1Label" => ecs_select[disabled: "deviceCustomFloatingPoint1Label", v1: "[cef][device_custom_floating_point_1][label]"],
      "cfp2"      => ecs_select[disabled: "deviceCustomFloatingPoint2",      v1: "[cef][device_custom_floating_point_2][value]"],
      "cfp2Label" => ecs_select[disabled: "deviceCustomFloatingPoint2Label", v1: "[cef][device_custom_floating_point_2][label]"],
      "cfp3"      => ecs_select[disabled: "deviceCustomFloatingPoint3",      v1: "[cef][device_custom_floating_point_3][value]"],
      "cfp3Label" => ecs_select[disabled: "deviceCustomFloatingPoint3Label", v1: "[cef][device_custom_floating_point_3][label]"],
      "cfp4"      => ecs_select[disabled: "deviceCustomFloatingPoint4",      v1: "[cef][device_custom_floating_point_4][value]"],
      "cfp4Label" => ecs_select[disabled: "deviceCustomFloatingPoint4Label", v1: "[cef][device_custom_floating_point_4][label]"],
      "cn1"       => ecs_select[disabled: "deviceCustomNumber1",             v1: "[cef][device_custom_number_1][value]"],
      "cn1Label"  => ecs_select[disabled: "deviceCustomNumber1Label",        v1: "[cef][device_custom_number_1][label]"],
      "cn2"       => ecs_select[disabled: "deviceCustomNumber2",             v1: "[cef][device_custom_number_2][value]"],
      "cn2Label"  => ecs_select[disabled: "deviceCustomNumber2Label",        v1: "[cef][device_custom_number_2][label]"],
      "cn3"       => ecs_select[disabled: "deviceCustomNumber3",             v1: "[cef][device_custom_number_3][value]"],
      "cn3Label"  => ecs_select[disabled: "deviceCustomNumber3Label",        v1: "[cef][device_custom_number_3][label]"],
      "cnt"       => ecs_select[disabled: "baseEventCount",                  v1: "[cef][base_event_count]"],
      "cs1"       => ecs_select[disabled: "deviceCustomString1",             v1: "[cef][device_custom_string_1][value]"],
      "cs1Label"  => ecs_select[disabled: "deviceCustomString1Label",        v1: "[cef][device_custom_string_1][label]"],
      "cs2"       => ecs_select[disabled: "deviceCustomString2",             v1: "[cef][device_custom_string_2][value]"],
      "cs2Label"  => ecs_select[disabled: "deviceCustomString2Label",        v1: "[cef][device_custom_string_2][label]"],
      "cs3"       => ecs_select[disabled: "deviceCustomString3",             v1: "[cef][device_custom_string_3][value]"],
      "cs3Label"  => ecs_select[disabled: "deviceCustomString3Label",        v1: "[cef][device_custom_string_3][label]"],
      "cs4"       => ecs_select[disabled: "deviceCustomString4",             v1: "[cef][device_custom_string_4][value]"],
      "cs4Label"  => ecs_select[disabled: "deviceCustomString4Label",        v1: "[cef][device_custom_string_4][label]"],
      "cs5"       => ecs_select[disabled: "deviceCustomString5",             v1: "[cef][device_custom_string_5][value]"],
      "cs5Label"  => ecs_select[disabled: "deviceCustomString5Label",        v1: "[cef][device_custom_string_5][label]"],
      "cs6"       => ecs_select[disabled: "deviceCustomString6",             v1: "[cef][device_custom_string_6][value]"],
      "cs6Label"  => ecs_select[disabled: "deviceCustomString6Label",        v1: "[cef][device_custom_string_6][label]"],
      "dhost"     => ecs_select[disabled: "destinationHostName",             v1: "[destination][domain]"],
      "dmac"      => ecs_select[disabled: "destinationMacAddress",           v1: "[destination][mac]"],
      "dntdom"    => ecs_select[disabled: "destinationNtDomain",             v1: "[destination][registered_domain]"],
      "dpid"      => ecs_select[disabled: "destinationProcessId",            v1: "[destination][process][pid]"],
      "dpriv"     => ecs_select[disabled: "destinationUserPrivileges",       v1: "[destination][user][group][name]"],
      "dproc"     => ecs_select[disabled: "destinationProcessName",          v1: "[destination][process][name]"],
      "dpt"       => ecs_select[disabled: "destinationPort",                 v1: "[destination][port]"],
      "dst"       => ecs_select[disabled: "destinationAddress",              v1: "[destination][ip]"],
      "duid"      => ecs_select[disabled: "destinationUserId",               v1: "[destination][user][id]"],
      "duser"     => ecs_select[disabled: "destinationUserName",             v1: "[destination][user][name]"],
      "dvc"       => ecs_select[disabled: "deviceAddress",                   v1: "[#{@device}][ip]"],
      "dvchost"   => ecs_select[disabled: "deviceHostName",                  v1: "[#{@device}][name]"],
      "dvcpid"    => ecs_select[disabled: "deviceProcessId",                 v1: "[process][pid]"],
      "end"       => ecs_select[disabled: "endTime",                         v1: "[event][end]"],
      "fname"     => ecs_select[disabled: "fileName",                        v1: "[file][name]"],
      "fsize"     => ecs_select[disabled: "fileSize",                        v1: "[file][size]"],
      "in"        => ecs_select[disabled: "bytesIn",                         v1: "[source][bytes]"],
      "msg"       => ecs_select[disabled: "message",                         v1: "[message]"],
      "out"       => ecs_select[disabled: "bytesOut",                        v1: "[destination][bytes]"],
      "outcome"   => ecs_select[disabled: "eventOutcome",                    v1: "[event][outcome]"],
      "proto"     => ecs_select[disabled: "transportProtocol",               v1: "[network][transport]"],
      "request"   => ecs_select[disabled: "requestUrl",                      v1: "[url][original]"],
      "rt"        => ecs_select[disabled: "deviceReceiptTime",               v1: "[@timestamp]"], # TODO: test the magic handling
      "shost"     => ecs_select[disabled: "sourceHostName",                  v1: "[source][domain]"],
      "smac"      => ecs_select[disabled: "sourceMacAddress",                v1: "[source][mac]"],
      "sntdom"    => ecs_select[disabled: "sourceNtDomain",                  v1: "[source][registered_domain]"], # TODO: if `sourceDnsDomain` not present?
      "spid"      => ecs_select[disabled: "sourceProcessId",                 v1: "[source][process][pid]"],
      "spriv"     => ecs_select[disabled: "sourceUserPrivileges",            v1: "[source][user][group][name]"],
      "sproc"     => ecs_select[disabled: "sourceProcessName",               v1: "[source][process][name]"],
      "spt"       => ecs_select[disabled: "sourcePort",                      v1: "[source][port]"],
      "src"       => ecs_select[disabled: "sourceAddress",                   v1: "[source][ip]"],
      "start"     => ecs_select[disabled: "startTime",                       v1: "[event][start]"],
      "suid"      => ecs_select[disabled: "sourceUserId",                    v1: "[source][user][id]"],
      "suser"     => ecs_select[disabled: "sourceUserName",                  v1: "[source][user][name]"],
      "ahost"     => ecs_select[disabled: "agentHostName",                   v1: "[agent][name]"],
      "art"       => ecs_select[disabled: "agentReceiptTime",                v1: "[event][created]"],
      "at"        => ecs_select[disabled: "agentType",                       v1: "[agent][type]"],
      "aid"       => ecs_select[disabled: "agentId",                         v1: "[agent][id]"],
      "_cefVer"   => ecs_select[disabled: "cefVersion",                      v1: "[cef][version]"],
      "agt"       => ecs_select[disabled: "agentAddress",                    v1: "[agent][ip]"],
      "av"        => ecs_select[disabled: "agentVersion",                    v1: "[agent][version]"],
      "atz"       => ecs_select[disabled: "agentTimeZone",                   v1: "[agent][type]"],
      "dtz"       => ecs_select[disabled: "destinationTimeZone",             v1: "[event][timezone]"],
      "slong"     => ecs_select[disabled: "sourceLongitude",                 v1: "[source][geo][location][lon]"],
      "slat"      => ecs_select[disabled: "sourceLatitude",                  v1: "[source][geo][location][lat]"],
      "dlong"     => ecs_select[disabled: "destinationLongitude",            v1: "[destination][geo][location][lon]"],
      "dlat"      => ecs_select[disabled: "destinationLatitude",             v1: "[destination][geo][location][lon]"],
      "catdt"     => ecs_select[disabled: "categoryDeviceType",              v1: "[cef][device_type]"],
      "mrt"       => ecs_select[disabled: "managerReceiptTime",              v1: "[event][ingested]"],
      "amac"      => ecs_select[disabled: "agentMacAddress",                 v1: "[agent][mac]"],
    }.freeze

    @mapping_inverted = @mapping.invert.freeze
  end

  if Gem::Requirement.new(">= 2.5.0").satisfied_by? Gem::Version.new(RUBY_VERSION)
    def delete_cef_prefix(cef_version)
      cef_version.delete_prefix(CEF_PREFIX)
    end
  else
    def delete_cef_prefix(cef_version)
      cef_version.start_with?(CEF_PREFIX) ? cef_version[CEF_PREFIX.length..-1] : cef_version
    end
  end

  class Chooser
    ##
    # @param supported_choices [Array[Symbol]]
    def initialize(supported_choices)
      @supported_choices = supported_choices.dup.freeze
    end

    ##
    # @param choice [Symbol]
    # @param error_name [#to_s] the name of this choice, to be used in case of an error
    # @param error_class [Exception] the exception class to use in case of an error
    # @return [Choice]
    def choose(choice, error_name="choice", error_class=ArgumentError)
      if !@supported_choices.include?(choice)
        message = sprintf("unsupported %s `%s`; expected one of %s", error_name, choice.to_s, @supported_choices.map(&:to_s))
        # logger.error(message)
        fail(error_class, message)
      end

      Choice.new(self, choice)
    end

    ##
    # Used when making a choice, ensures that the providing code supplies all possible choices.
    # @see Choice#value_from
    # @api private
    def validate!(defined_choices)
      missing = @supported_choices - defined_choices
      fail(ArgumentError, "missing required options #{missing}") if missing.any?

      unknown = defined_choices - @supported_choices
      fail(ArgumentError, "unsupported options #{unknown}") if unknown.any?
    end

    ##
    # A `Choice` represents a chosen value from the set supported by its `Chooser`.
    # It can be used to safely select a value from a mapping at runtime using `Choice#value_from`.
    class Choice

      ##
      # @api private
      # @see Chooser#choice
      #
      # @param chooser [Chooser]
      # @param choice [Symbol]
      def initialize(chooser, choice)
        @chooser = chooser
        @choice = choice
      end

      ##
      # With the current choice value, select one of the provided options.
      # @param options [Hash{Symbol=>Object}]: the options to chose between.
      #                                        it is an `ArgumentError` to provide a different set of
      #                                        options than those this `Chooser` was initialized with.
      #                                        This ensures that all reachable code implements all
      #                                        supported options.
      # @return [Object]
      def value_from(options)
        @chooser.validate!(options.keys)
        options.fetch(@choice)
      end
      alias_method :[], :value_from
    end
  end
end
