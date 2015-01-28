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

    it "should parse the cef header" do
      subject.decode(message) do |e|
        insist { e.is_a?(LogStash::Event) }
        insist { e["cef_version"] } == "0"
        insist { e["cef_vendor"] } == "security"
        insist { e["cef_product"] } == "threatmanager"
        insist { e["cef_device_version"] } == "1.0"
        insist { e["cef_sigid"] } == "100"
        insist { e["cef_name"] } == "trojan successfully stopped"
        insist { e["cef_severity"] } == "10"
        insist { e["message"] } == "src=10.0.0.192 dst=12.121.122.82 spt=1232"
      end
    end

    it "should parse the cef body" do
      subject.decode(message) do |e|
        insist { e["cef_ext_src"] } == "10.0.0.192"
        insist { e["cef_ext_dst"] } == "12.121.122.82"
        insist { e["cef_ext_spt"] } == "1232"
      end
    end

    it "should handle values in the body that contain spaces"
  end

end
