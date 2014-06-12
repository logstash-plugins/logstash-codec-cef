require "logstash/filters/base"
require "logstash/namespace"

# This filter helps automatically parse CEF logs
class LogStash::Filters::CEF < LogStash::Filters::Base
  config_name "cef"
  milestone 1
  config :syslog, :validate => :boolean, :default => false

  def register
  end

  def filter(event)
    return unless filter?(event)

    # Need to break out the headers, then return the headers as individual fields, and the extension to be processed by a filter (ie: KV)
    # %{SYSLOGDATE} %{HOST} CEF:Version|Device Vendor|Device Product|Device Version|SignatureID|Name|Severity|Extension
    data = event['message']
    head, data = data.split('CEF:', 2)
    if @syslog
        @logger.debug("Expecting SYSLOG headers")
        event['syslog'] = head
    end #if @syslog
    # Now, break out the rest of the headers
    event['cef_version'], event['cef_vendor'], event['cef_product'], event['cef_device_version'], event['cef_sigid'], event['cef_name'], event['cef_severity'], message =  data.scan /(?:[^\|\\]|\\.)+/
    # Now, try to break out the Extension Dictionary
    if message.to_s.strip.length != 0
      message = message.split(/ ([\w\.]+)=/)

      key, value = message.shift.split('=',2)
      @logger.debug(message)
      kv = Hash[*message]
      @logger.debug(kv)
      addKey(kv,key,value)
      event.to_hash.merge!(Hash[kv.map{|k,v| ["cef_ext_"+k,v]}])
    end #
    filter_matched(event)  
  end

  private
  def addKey(kv_keys, key, value)
    if kv_keys.has_key?(key)
      if kv_keys[key].is_a? Array
        kv_keys[key].push(value)
      else
        kv_keys[key] = [kv_keys[key], value]
      end
    else
      kv_keys[key] = value
    end
  end # addKey
end # class LogStash::Filters::cef
