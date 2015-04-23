# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/cef"
require "logstash/event"

describe LogStash::Codecs::CEF do
  subject do
    next LogStash::Codecs::CEF.new
  end

  context "#encode" do
    it "should assert all header fields are present"
  end

  context "#decode" do
    let (:message) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }

    def validate(e) 
      insist { e.is_a?(LogStash::Event) }
      insist { e['cef_version'] } == "0"
      insist { e['cef_device_version'] } == "1.0"
      insist { e['cef_sigid'] } == "100"
      insist { e['cef_name'] } == "trojan successfully stopped"
      insist { e['cef_severity'] } == "10"
    end

    it "should parse the cef headers" do
      subject.decode(message) do |e|
        validate(e)
        ext = e['cef_ext']
        insist { e["cef_vendor"] } == "security"
        insist { e["cef_product"] } == "threatmanager"
      end
    end

    it "should parse the cef body" do
      subject.decode(message) do |e|
        ext = e['cef_ext']
        insist { ext['src'] } == "10.0.0.192"
        insist { ext['dst'] } == "12.121.122.82"
        insist { ext['spt'] } == "1232"
      end
    end

    let (:missing_headers) { "CEF:0|||1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should be OK with missing CEF headers (multiple pipes in sequence)" do
      subject.decode(missing_headers) do |e|
        validate(e)
        insist { e["cef_vendor"] } == ""
        insist { e["cef_product"] } == ""
      end 
    end

    let (:leading_whitespace) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "should strip leading whitespace from the message" do
      subject.decode(leading_whitespace) do |e|
        validate(e)
      end 
    end

    let (:escaped_pipes) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this\|has an escaped pipe' }
    it "should be OK with escaped pipes in the message" do
      subject.decode(escaped_pipes) do |e|
        ext = e['cef_ext']
        insist { ext['moo'] } == 'this\|has an escaped pipe'
      end 
    end

    let (:syslog) { "Syslogdate Sysloghost CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
    it "Should detect headers before CEF starts" do
      subject.decode(syslog) do |e|
        validate(e)
        insist { e['syslog'] } == 'Syslogdate Sysloghost'
      end 
    end

  end

end
