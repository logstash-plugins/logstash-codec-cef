require "logstash/codecs/base"

class LogStash::Codecs::CEF < LogStash::Codecs::Base
  config_name "cef"
  config :signature, :validate => :string, :default => "Logstash"
  config :name, :validate => :string, :default => "Logstash"
  config :sev, :validate => :number, :default => 6

  config :fields, :validate => :array

  public
  def initialize(params={})
    super(params)
  end

  public
  def decode(data)
    # Strip any quotations at the start and end, flex connectors seem to send this
    if data[0] == "\""
      data = data[1..-2]
    end
    event = LogStash::Event.new

    # Split by the pipes
    event['cef_version'], event['cef_vendor'], event['cef_product'], event['cef_device_version'], event['cef_sigid'], event['cef_name'], event['cef_severity'], *message = data.split /(?<!\\)[\|]/
    message = message.join()
    # Try and parse out the syslog header if there is one
    if event['cef_version'].include? ' '
      event['syslog'], unused, event['cef_version'] = event['cef_version'].rpartition(' ')
    end

    # Get rid of the CEF bit in the version
    event['cef_version'].sub! /^CEF:/, ''

    # Strip any whitespace from the message
    if not message.nil? and message.include? '='
      message = message.strip

      # If the last KVP has no value, add an empty string, this prevents hash errors below
      if message.end_with?("=")
        message=message + ' '
      end

      # Now parse the key value pairs into it
      extensions = {}
      message = message.split(/ ([\w\.]+)=/)
      key, value = message.shift.split('=', 2)
      extensions[key] = value

      Hash[*message].each{ |k, v| extensions[k] = v }

      # And save the new has as the extensions
      event['cef_ext'] = extensions
    end

    yield event
  end

  public
  def encode(data)
    # "CEF:0|Elasticsearch|Logstash|1.0|Signature|Name|Sev|"

    # TODO: Need to check that fields are set!

    # Signature, Name, and Sev should be set in the config, with ref to fields
    # Should also probably set the fields sent
    header = ["CEF:0", "Elasticsearch", "Logstash", "1.0", @signature, @name, @sev].join("|")
    values = @fields.map {|name| get_value(name, data)}.join(" ")
    # values = values.map {|k,v| "#{k}=#{v}"}.join(" ")
    @on_event.call(header + " " + values + "\n")
  end

  private
  def get_value(name, event)
    val = event[name]
    case val
    when Hash
      return name + "=" + val.to_json
    else
      return name + "=" + val
    end
  end

end
