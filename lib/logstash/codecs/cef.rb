require "logstash/codecs/base"
require "logstash/codecs/line"

class LogStash::Codecs::CEF < LogStash::Codecs::Base
  config_name "cef"

  milestone 1

  # Specify if the Syslog header will be expected
  config :syslog, :validate => :boolean, :default => false

  public
  def initialize(params={})
    super(params)
  end

  public
  def decode(data)
    # Need to break out the headers, then return the headers as individual fields, and the extension to be processed by a filter (ie: KV)
    # %{SYSLOGDATE} %{HOST} CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
    event = LogStash::Event.new()
    if @syslog
        @logger.debug("Expecting SYSLOG headers")
        event['syslog'], data = data.split('CEF:', 1)
        # Since we have the syslog headers, lets pull them out first and put them into their own field to be handled
    else 
        # We don't have syslog headers, so we just need to remove CEF:
        data.sub! /^CEF:/, ''
    end #if @syslog
    # Now, break out the rest of the headers
    event['cef_version'], event['cef_vendor'], event['cef_product'], event['cef_device_version'], event['cef_sigid'], event['cef_name'], event['cef_severity'], event['message'] =  data.scan /(?:[^\|\\]|\\.)+/
    yield event
  end

#  public
#  def encode(data)
	# Do stuff here
#  end

end
