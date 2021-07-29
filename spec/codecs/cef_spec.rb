# encoding: utf-8
require 'logstash/util'
require "logstash/devutils/rspec/spec_helper"
require "insist"
require "logstash/codecs/cef"
require "logstash/event"
require "json"

require 'logstash/plugin_mixins/ecs_compatibility_support/spec_helper'

describe LogStash::Codecs::CEF do
  subject(:codec) do
    next LogStash::Codecs::CEF.new
  end

  context "#encode", :ecs_compatibility_support do
    subject(:codec) { LogStash::Codecs::CEF.new }

    let(:results)   { [] }

    context "with delimiter set" do
      # '\r\n' in single quotes to simulate the real input from a config
      # containing \r\n as 4-character sequence in the config:
      #
      #   delimiter => "\r\n"
      #
      # Related: https://github.com/elastic/logstash/issues/1645
      subject(:codec) { LogStash::Codecs::CEF.new("delimiter" => '\r\n') }

      it "should append the delimiter to the result" do
        codec.on_event { |data, newdata| results << newdata }
        codec.encode(LogStash::Event.new({}))
        expect(results.first).to end_with("\r\n")
      end
    end

    it "should not fail if fields is nil" do
      codec.on_event{|data, newdata| results << newdata}
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should assert all header fields are present" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default values for empty header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = ""
      codec.product = ""
      codec.version = ""
      codec.signature = ""
      codec.name = ""
      codec.severity = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use configured values for header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "vendor"
      codec.product = "product"
      codec.version = "2.0"
      codec.signature = "signature"
      codec.name = "name"
      codec.severity = "1"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|vendor\|product\|2.0\|signature\|name\|1\|$/m)
    end

    it "should use sprintf for header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "%{vendor}"
      codec.product = "%{product}"
      codec.version = "%{version}"
      codec.signature = "%{signature}"
      codec.name = "%{name}"
      codec.severity = "%{severity}"
      codec.fields = []
      event = LogStash::Event.new("vendor" => "vendor", "product" => "product", "version" => "2.0", "signature" => "signature", "name" => "name", "severity" => "1")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|vendor\|product\|2.0\|signature\|name\|1\|$/m)
    end

    it "should use default, if severity is not numeric" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "foo"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default, if severity is > 10" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "11"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default, if severity is < 0" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "-1"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should use default, if severity is float with decimal part" do
      codec.on_event{|data, newdata| results << newdata}
      codec.severity = "5.4"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
    end

    it "should append fields as key/value pairs in cef extension part" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar" ]
      event = LogStash::Event.new("foo" => "foo value", "bar" => "bar value")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo value bar=bar value$/m)
    end

    it "should ignore fields in fields if not present in event" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar", "baz" ]
      event = LogStash::Event.new("foo" => "foo value", "baz" => "baz value")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo value baz=baz value$/m)
    end

    it "should sanitize header fields" do
      codec.on_event{|data, newdata| results << newdata}
      codec.vendor = "ven\ndor"
      codec.product = "pro|duct"
      codec.version = "ver\\sion"
      codec.signature = "sig\r\nnature"
      codec.name = "na\rme"
      codec.severity = "4\n"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|ven dor\|pro\\\|duct\|ver\\\\sion\|sig nature\|na me\|4\|$/m)
    end

    it "should sanitize extension keys" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "f o\no", "@b-a_r" ]
      event = LogStash::Event.new("f o\no" => "foo value", "@b-a_r" => "bar value")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo value bar=bar value$/m)
    end

    it "should sanitize extension values" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo", "bar", "baz" ]
      event = LogStash::Event.new("foo" => "foo\\value\n", "bar" => "bar=value\r")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=foo\\\\value\\n bar=bar\\=value\\n$/m)
    end

    it "should encode a hash value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => { "bar" => "bar value", "baz" => "baz value" })
      codec.encode(event)
      foo = results.first[/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_hash = JSON.parse(foo)
      expect(foo_hash).to eq({"bar" => "bar value", "baz" => "baz value"})
    end

    it "should encode an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ "bar", "baz" ])
      codec.encode(event)
      foo = results.first[/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_array = JSON.parse(foo)
      expect(foo_array).to eq(["bar", "baz"])
    end

    it "should encode a hash in an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ { "bar" => "bar value" }, "baz" ])
      codec.encode(event)
      foo = results.first[/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=(.*)$/, 1]
      expect(foo).not_to be_nil
      foo_array = JSON.parse(foo)
      expect(foo_array).to eq([{"bar" => "bar value"}, "baz"])
    end

    it "should encode a LogStash::Timestamp" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => LogStash::Timestamp.new)
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=[0-9TZ.:-]+$/m)
    end

    ecs_compatibility_matrix(:disabled,:v1) do |ecs_select|
      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      it "should encode the CEF field names to their long versions" do
        # This is with the default value of "reverse_mapping" that is "false".
        codec.on_event{|data, newdata| results << newdata}
        codec.fields = [ "deviceAction", "applicationProtocol", "deviceCustomIPv6Address1", "deviceCustomIPv6Address1Label", "deviceCustomIPv6Address2", "deviceCustomIPv6Address2Label", "deviceCustomIPv6Address3", "deviceCustomIPv6Address3Label", "deviceCustomIPv6Address4", "deviceCustomIPv6Address4Label", "deviceEventCategory", "deviceCustomFloatingPoint1", "deviceCustomFloatingPoint1Label", "deviceCustomFloatingPoint2", "deviceCustomFloatingPoint2Label", "deviceCustomFloatingPoint3", "deviceCustomFloatingPoint3Label", "deviceCustomFloatingPoint4", "deviceCustomFloatingPoint4Label", "deviceCustomNumber1", "deviceCustomNumber1Label", "deviceCustomNumber2", "deviceCustomNumber2Label", "deviceCustomNumber3", "deviceCustomNumber3Label", "baseEventCount", "deviceCustomString1", "deviceCustomString1Label", "deviceCustomString2", "deviceCustomString2Label", "deviceCustomString3", "deviceCustomString3Label", "deviceCustomString4", "deviceCustomString4Label", "deviceCustomString5", "deviceCustomString5Label", "deviceCustomString6", "deviceCustomString6Label", "destinationHostName", "destinationMacAddress", "destinationNtDomain", "destinationProcessId", "destinationUserPrivileges", "destinationProcessName", "destinationPort", "destinationAddress", "destinationUserId", "destinationUserName", "deviceAddress", "deviceHostName", "deviceProcessId", "endTime", "fileName", "fileSize", "bytesIn", "message", "bytesOut", "eventOutcome", "transportProtocol", "requestUrl", "deviceReceiptTime", "sourceHostName", "sourceMacAddress", "sourceNtDomain", "sourceProcessId", "sourceUserPrivileges", "sourceProcessName", "sourcePort", "sourceAddress", "startTime", "sourceUserId", "sourceUserName", "agentHostName", "agentReceiptTime", "agentType", "agentId", "agentAddress", "agentVersion", "agentTimeZone", "destinationTimeZone", "sourceLongitude", "sourceLatitude", "destinationLongitude", "destinationLatitude", "categoryDeviceType", "managerReceiptTime", "agentMacAddress" ]
        event = LogStash::Event.new("deviceAction" => "foobar", "applicationProtocol" => "foobar", "deviceCustomIPv6Address1" => "foobar", "deviceCustomIPv6Address1Label" => "foobar", "deviceCustomIPv6Address2" => "foobar", "deviceCustomIPv6Address2Label" => "foobar", "deviceCustomIPv6Address3" => "foobar", "deviceCustomIPv6Address3Label" => "foobar", "deviceCustomIPv6Address4" => "foobar", "deviceCustomIPv6Address4Label" => "foobar", "deviceEventCategory" => "foobar", "deviceCustomFloatingPoint1" => "foobar", "deviceCustomFloatingPoint1Label" => "foobar", "deviceCustomFloatingPoint2" => "foobar", "deviceCustomFloatingPoint2Label" => "foobar", "deviceCustomFloatingPoint3" => "foobar", "deviceCustomFloatingPoint3Label" => "foobar", "deviceCustomFloatingPoint4" => "foobar", "deviceCustomFloatingPoint4Label" => "foobar", "deviceCustomNumber1" => "foobar", "deviceCustomNumber1Label" => "foobar", "deviceCustomNumber2" => "foobar", "deviceCustomNumber2Label" => "foobar", "deviceCustomNumber3" => "foobar", "deviceCustomNumber3Label" => "foobar", "baseEventCount" => "foobar", "deviceCustomString1" => "foobar", "deviceCustomString1Label" => "foobar", "deviceCustomString2" => "foobar", "deviceCustomString2Label" => "foobar", "deviceCustomString3" => "foobar", "deviceCustomString3Label" => "foobar", "deviceCustomString4" => "foobar", "deviceCustomString4Label" => "foobar", "deviceCustomString5" => "foobar", "deviceCustomString5Label" => "foobar", "deviceCustomString6" => "foobar", "deviceCustomString6Label" => "foobar", "destinationHostName" => "foobar", "destinationMacAddress" => "foobar", "destinationNtDomain" => "foobar", "destinationProcessId" => "foobar", "destinationUserPrivileges" => "foobar", "destinationProcessName" => "foobar", "destinationPort" => "foobar", "destinationAddress" => "foobar", "destinationUserId" => "foobar", "destinationUserName" => "foobar", "deviceAddress" => "foobar", "deviceHostName" => "foobar", "deviceProcessId" => "foobar", "endTime" => "foobar", "fileName" => "foobar", "fileSize" => "foobar", "bytesIn" => "foobar", "message" => "foobar", "bytesOut" => "foobar", "eventOutcome" => "foobar", "transportProtocol" => "foobar", "requestUrl" => "foobar", "deviceReceiptTime" => "foobar", "sourceHostName" => "foobar", "sourceMacAddress" => "foobar", "sourceNtDomain" => "foobar", "sourceProcessId" => "foobar", "sourceUserPrivileges" => "foobar", "sourceProcessName"=> "foobar", "sourcePort" => "foobar", "sourceAddress" => "foobar", "startTime" => "foobar", "sourceUserId" => "foobar", "sourceUserName" => "foobar", "agentHostName" => "foobar", "agentReceiptTime" => "foobar", "agentType" => "foobar", "agentId" => "foobar", "agentAddress" => "foobar", "agentVersion" => "foobar", "agentTimeZone" => "foobar", "destinationTimeZone" => "foobar", "sourceLongitude" => "foobar", "sourceLatitude" => "foobar", "destinationLongitude" => "foobar", "destinationLatitude" => "foobar", "categoryDeviceType" => "foobar", "managerReceiptTime" => "foobar", "agentMacAddress" => "foobar")
        codec.encode(event)
        expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|deviceAction=foobar applicationProtocol=foobar deviceCustomIPv6Address1=foobar deviceCustomIPv6Address1Label=foobar deviceCustomIPv6Address2=foobar deviceCustomIPv6Address2Label=foobar deviceCustomIPv6Address3=foobar deviceCustomIPv6Address3Label=foobar deviceCustomIPv6Address4=foobar deviceCustomIPv6Address4Label=foobar deviceEventCategory=foobar deviceCustomFloatingPoint1=foobar deviceCustomFloatingPoint1Label=foobar deviceCustomFloatingPoint2=foobar deviceCustomFloatingPoint2Label=foobar deviceCustomFloatingPoint3=foobar deviceCustomFloatingPoint3Label=foobar deviceCustomFloatingPoint4=foobar deviceCustomFloatingPoint4Label=foobar deviceCustomNumber1=foobar deviceCustomNumber1Label=foobar deviceCustomNumber2=foobar deviceCustomNumber2Label=foobar deviceCustomNumber3=foobar deviceCustomNumber3Label=foobar baseEventCount=foobar deviceCustomString1=foobar deviceCustomString1Label=foobar deviceCustomString2=foobar deviceCustomString2Label=foobar deviceCustomString3=foobar deviceCustomString3Label=foobar deviceCustomString4=foobar deviceCustomString4Label=foobar deviceCustomString5=foobar deviceCustomString5Label=foobar deviceCustomString6=foobar deviceCustomString6Label=foobar destinationHostName=foobar destinationMacAddress=foobar destinationNtDomain=foobar destinationProcessId=foobar destinationUserPrivileges=foobar destinationProcessName=foobar destinationPort=foobar destinationAddress=foobar destinationUserId=foobar destinationUserName=foobar deviceAddress=foobar deviceHostName=foobar deviceProcessId=foobar endTime=foobar fileName=foobar fileSize=foobar bytesIn=foobar message=foobar bytesOut=foobar eventOutcome=foobar transportProtocol=foobar requestUrl=foobar deviceReceiptTime=foobar sourceHostName=foobar sourceMacAddress=foobar sourceNtDomain=foobar sourceProcessId=foobar sourceUserPrivileges=foobar sourceProcessName=foobar sourcePort=foobar sourceAddress=foobar startTime=foobar sourceUserId=foobar sourceUserName=foobar agentHostName=foobar agentReceiptTime=foobar agentType=foobar agentId=foobar agentAddress=foobar agentVersion=foobar agentTimeZone=foobar destinationTimeZone=foobar sourceLongitude=foobar sourceLatitude=foobar destinationLongitude=foobar destinationLatitude=foobar categoryDeviceType=foobar managerReceiptTime=foobar agentMacAddress=foobar$/m)
      end

      if ecs_select.active_mode != :disabled
        let(:event_flat_hash) do
          {
            "[event][action]" => "floop", # deviceAction
            "[network][protocol]" => "https", # applicationProtocol
            "[cef][device_custom_ipv6_address_1][value]" => "4302:c0a5:0bb9:2dfd:7b4e:97f7:a328:98a9", # deviceCustomIPv6Address1
            "[cef][device_custom_ipv6_address_1][label]" => "internal-interface", # deviceCustomIPv6Address1Label
            "[observer][ip]" => "123.45.67.89", # deviceAddress
            "[observer][hostname]" => "banana", # deviceHostName
            "[user_agent][original]" => "'Foo-Bar/2018.1.7; Email:user@example.com; Guid:test='", # requestClientApplication
            "[source][registered_domain]" => "monkey.see" # sourceDnsDomain
          }
        end

        let(:event) do
          event_flat_hash.each_with_object(LogStash::Event.new) do |(fr,v),memo|
            memo.set(fr, v)
          end
        end

        it 'encodes the ECS field names to their CEF name' do
          codec.on_event{|data, newdata| results << newdata}
          codec.fields = event_flat_hash.keys

          codec.encode(event)

          expect(results.first).to match(%r{^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|deviceAction=floop applicationProtocol=https deviceCustomIPv6Address1=4302:c0a5:0bb9:2dfd:7b4e:97f7:a328:98a9 deviceCustomIPv6Address1Label=internal-interface deviceAddress=123\.45\.67\.89 deviceHostName=banana requestClientApplication='Foo-Bar/2018\.1\.7; Email:user@example\.com; Guid:test\\=' sourceDnsDomain=monkey.see$}m)
        end
      end

      context "with reverse_mapping set to true" do
        subject(:codec) { LogStash::Codecs::CEF.new("reverse_mapping" => true) }

        it "should encode the CEF field names to their short versions" do
          codec.on_event{|data, newdata| results << newdata}
          codec.fields = [ "deviceAction", "applicationProtocol", "deviceCustomIPv6Address1", "deviceCustomIPv6Address1Label", "deviceCustomIPv6Address2", "deviceCustomIPv6Address2Label", "deviceCustomIPv6Address3", "deviceCustomIPv6Address3Label", "deviceCustomIPv6Address4", "deviceCustomIPv6Address4Label", "deviceEventCategory", "deviceCustomFloatingPoint1", "deviceCustomFloatingPoint1Label", "deviceCustomFloatingPoint2", "deviceCustomFloatingPoint2Label", "deviceCustomFloatingPoint3", "deviceCustomFloatingPoint3Label", "deviceCustomFloatingPoint4", "deviceCustomFloatingPoint4Label", "deviceCustomNumber1", "deviceCustomNumber1Label", "deviceCustomNumber2", "deviceCustomNumber2Label", "deviceCustomNumber3", "deviceCustomNumber3Label", "baseEventCount", "deviceCustomString1", "deviceCustomString1Label", "deviceCustomString2", "deviceCustomString2Label", "deviceCustomString3", "deviceCustomString3Label", "deviceCustomString4", "deviceCustomString4Label", "deviceCustomString5", "deviceCustomString5Label", "deviceCustomString6", "deviceCustomString6Label", "destinationHostName", "destinationMacAddress", "destinationNtDomain", "destinationProcessId", "destinationUserPrivileges", "destinationProcessName", "destinationPort", "destinationAddress", "destinationUserId", "destinationUserName", "deviceAddress", "deviceHostName", "deviceProcessId", "endTime", "fileName", "fileSize", "bytesIn", "message", "bytesOut", "eventOutcome", "transportProtocol", "requestUrl", "deviceReceiptTime", "sourceHostName", "sourceMacAddress", "sourceNtDomain", "sourceProcessId", "sourceUserPrivileges", "sourceProcessName", "sourcePort", "sourceAddress", "startTime", "sourceUserId", "sourceUserName", "agentHostName", "agentReceiptTime", "agentType", "agentId", "agentAddress", "agentVersion", "agentTimeZone", "destinationTimeZone", "sourceLongitude", "sourceLatitude", "destinationLongitude", "destinationLatitude", "categoryDeviceType", "managerReceiptTime", "agentMacAddress" ]
          event = LogStash::Event.new("deviceAction" => "foobar", "applicationProtocol" => "foobar", "deviceCustomIPv6Address1" => "foobar", "deviceCustomIPv6Address1Label" => "foobar", "deviceCustomIPv6Address2" => "foobar", "deviceCustomIPv6Address2Label" => "foobar", "deviceCustomIPv6Address3" => "foobar", "deviceCustomIPv6Address3Label" => "foobar", "deviceCustomIPv6Address4" => "foobar", "deviceCustomIPv6Address4Label" => "foobar", "deviceEventCategory" => "foobar", "deviceCustomFloatingPoint1" => "foobar", "deviceCustomFloatingPoint1Label" => "foobar", "deviceCustomFloatingPoint2" => "foobar", "deviceCustomFloatingPoint2Label" => "foobar", "deviceCustomFloatingPoint3" => "foobar", "deviceCustomFloatingPoint3Label" => "foobar", "deviceCustomFloatingPoint4" => "foobar", "deviceCustomFloatingPoint4Label" => "foobar", "deviceCustomNumber1" => "foobar", "deviceCustomNumber1Label" => "foobar", "deviceCustomNumber2" => "foobar", "deviceCustomNumber2Label" => "foobar", "deviceCustomNumber3" => "foobar", "deviceCustomNumber3Label" => "foobar", "baseEventCount" => "foobar", "deviceCustomString1" => "foobar", "deviceCustomString1Label" => "foobar", "deviceCustomString2" => "foobar", "deviceCustomString2Label" => "foobar", "deviceCustomString3" => "foobar", "deviceCustomString3Label" => "foobar", "deviceCustomString4" => "foobar", "deviceCustomString4Label" => "foobar", "deviceCustomString5" => "foobar", "deviceCustomString5Label" => "foobar", "deviceCustomString6" => "foobar", "deviceCustomString6Label" => "foobar", "destinationHostName" => "foobar", "destinationMacAddress" => "foobar", "destinationNtDomain" => "foobar", "destinationProcessId" => "foobar", "destinationUserPrivileges" => "foobar", "destinationProcessName" => "foobar", "destinationPort" => "foobar", "destinationAddress" => "foobar", "destinationUserId" => "foobar", "destinationUserName" => "foobar", "deviceAddress" => "foobar", "deviceHostName" => "foobar", "deviceProcessId" => "foobar", "endTime" => "foobar", "fileName" => "foobar", "fileSize" => "foobar", "bytesIn" => "foobar", "message" => "foobar", "bytesOut" => "foobar", "eventOutcome" => "foobar", "transportProtocol" => "foobar", "requestUrl" => "foobar", "deviceReceiptTime" => "foobar", "sourceHostName" => "foobar", "sourceMacAddress" => "foobar", "sourceNtDomain" => "foobar", "sourceProcessId" => "foobar", "sourceUserPrivileges" => "foobar", "sourceProcessName"=> "foobar", "sourcePort" => "foobar", "sourceAddress" => "foobar", "startTime" => "foobar", "sourceUserId" => "foobar", "sourceUserName" => "foobar", "agentHostName" => "foobar", "agentReceiptTime" => "foobar", "agentType" => "foobar", "agentId" => "foobar", "agentAddress" => "foobar", "agentVersion" => "foobar", "agentTimeZone" => "foobar", "destinationTimeZone" => "foobar", "sourceLongitude" => "foobar", "sourceLatitude" => "foobar", "destinationLongitude" => "foobar", "destinationLatitude" => "foobar", "categoryDeviceType" => "foobar", "managerReceiptTime" => "foobar", "agentMacAddress" => "foobar")
          codec.encode(event)
          expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|act=foobar app=foobar c6a1=foobar c6a1Label=foobar c6a2=foobar c6a2Label=foobar c6a3=foobar c6a3Label=foobar c6a4=foobar c6a4Label=foobar cat=foobar cfp1=foobar cfp1Label=foobar cfp2=foobar cfp2Label=foobar cfp3=foobar cfp3Label=foobar cfp4=foobar cfp4Label=foobar cn1=foobar cn1Label=foobar cn2=foobar cn2Label=foobar cn3=foobar cn3Label=foobar cnt=foobar cs1=foobar cs1Label=foobar cs2=foobar cs2Label=foobar cs3=foobar cs3Label=foobar cs4=foobar cs4Label=foobar cs5=foobar cs5Label=foobar cs6=foobar cs6Label=foobar dhost=foobar dmac=foobar dntdom=foobar dpid=foobar dpriv=foobar dproc=foobar dpt=foobar dst=foobar duid=foobar duser=foobar dvc=foobar dvchost=foobar dvcpid=foobar end=foobar fname=foobar fsize=foobar in=foobar msg=foobar out=foobar outcome=foobar proto=foobar request=foobar rt=foobar shost=foobar smac=foobar sntdom=foobar spid=foobar spriv=foobar sproc=foobar spt=foobar src=foobar start=foobar suid=foobar suser=foobar ahost=foobar art=foobar at=foobar aid=foobar agt=foobar av=foobar atz=foobar dtz=foobar slong=foobar slat=foobar dlong=foobar dlat=foobar catdt=foobar mrt=foobar amac=foobar$/m)
        end

        if ecs_select.active_mode != :disabled
          let(:event_flat_hash) do
            {
              "[event][action]" => "floop", # act
              "[network][protocol]" => "https", # app
              "[cef][device_custom_ipv6_address_1][value]" => "4302:c0a5:0bb9:2dfd:7b4e:97f7:a328:98a9", # c6a1
              "[cef][device_custom_ipv6_address_1][label]" => "internal-interface", # c6a1Label
              "[observer][ip]" => "123.45.67.89", # dvc
              "[observer][hostname]" => "banana", # dvchost
              "[user_agent][original]" => "'Foo-Bar/2018.1.7; Email:user@example.com; Guid:test='",
              "[source][registered_domain]" => "monkey.see" # sourceDnsDomain
            }
          end

          let(:event) do
            event_flat_hash.each_with_object(LogStash::Event.new) do |(fr,v),memo|
              memo.set(fr, v)
            end
          end


          it 'encodes the ECS field names to their CEF keys' do
            codec.on_event{|data, newdata| results << newdata}
            codec.fields = event_flat_hash.keys

            codec.encode(event)

            expect(results.first).to match(%r{^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|act=floop app=https c6a1=4302:c0a5:0bb9:2dfd:7b4e:97f7:a328:98a9 c6a1Label=internal-interface dvc=123\.45\.67\.89 dvchost=banana requestClientApplication='Foo-Bar/2018\.1\.7; Email:user@example\.com; Guid:test\\=' sourceDnsDomain=monkey.see$}m)
          end
        end
      end
    end
  end

  context "sanitize header field" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_header_field, "foo")).to be == "foo"
      expect(codec.send(:sanitize_header_field, "foo\nbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\rbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\r\nbar")).to be == "foo bar"
      expect(codec.send(:sanitize_header_field, "foo\r\nbar\r\nbaz")).to be == "foo bar baz"
      expect(codec.send(:sanitize_header_field, "foo\\bar")).to be == "foo\\\\bar"
      expect(codec.send(:sanitize_header_field, "foo|bar")).to be == "foo\\|bar"
      expect(codec.send(:sanitize_header_field, "foo=bar")).to be == "foo=bar"
      expect(codec.send(:sanitize_header_field, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_header_field, 123.123)).to be == "123.123" # Input value is a Float
      expect(codec.send(:sanitize_header_field, [])).to be == "[]" # Input value is an Array
      expect(codec.send(:sanitize_header_field, {})).to be == "{}" # Input value is a Hash
    end
  end

  context "sanitize extension key" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_extension_key, " foo ")).to be == "foo"
      expect(codec.send(:sanitize_extension_key, " FOO 123 ")).to be == "FOO123"
      expect(codec.send(:sanitize_extension_key, "foo\nbar\rbaz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, "Foo_Bar\r\nBaz")).to be == "FooBarBaz"
      expect(codec.send(:sanitize_extension_key, "foo-@bar=baz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, "[foo]|bar.baz")).to be == "foobarbaz"
      expect(codec.send(:sanitize_extension_key, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_extension_key, 123.123)).to be == "123123" # Input value is a Float, "." is not allowed and therefore removed
      expect(codec.send(:sanitize_extension_key, [])).to be == "" # Input value is an Array, "[" and "]" are not allowed and therefore removed
      expect(codec.send(:sanitize_extension_key, {})).to be == "" # Input value is a Hash, "{" and "}" are not allowed and therefore removed
    end
  end

  context "sanitize extension value" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should sanitize" do
      expect(codec.send(:sanitize_extension_val, "foo")).to be == "foo"
      expect(codec.send(:sanitize_extension_val, "foo\nbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\rbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\r\nbar")).to be == "foo\\nbar"
      expect(codec.send(:sanitize_extension_val, "foo\r\nbar\r\nbaz")).to be == "foo\\nbar\\nbaz"
      expect(codec.send(:sanitize_extension_val, "foo\\bar")).to be == "foo\\\\bar"
      expect(codec.send(:sanitize_extension_val, "foo|bar")).to be == "foo|bar"
      expect(codec.send(:sanitize_extension_val, "foo=bar")).to be == "foo\\=bar"
      expect(codec.send(:sanitize_extension_val, 123)).to be == "123" # Input value is a Fixnum
      expect(codec.send(:sanitize_extension_val, 123.123)).to be == "123.123" # Input value is a Float
      expect(codec.send(:sanitize_extension_val, [])).to be == "[]" # Input value is an Array
      expect(codec.send(:sanitize_extension_val, {})).to be == "{}" # Input value is a Hash
    end
  end

  context "valid_severity?" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    it "should validate severity" do
      expect(codec.send(:valid_severity?, nil)).to be == false
      expect(codec.send(:valid_severity?, "")).to be == false
      expect(codec.send(:valid_severity?, "foo")).to be == false
      expect(codec.send(:valid_severity?, "1.5")).to be == false
      expect(codec.send(:valid_severity?, "-1")).to be == false
      expect(codec.send(:valid_severity?, "11")).to be == false
      expect(codec.send(:valid_severity?, "0")).to be == true
      expect(codec.send(:valid_severity?, "10")).to be == true
      expect(codec.send(:valid_severity?, "1.0")).to be == true
      expect(codec.send(:valid_severity?, 1)).to be == true
      expect(codec.send(:valid_severity?, 1.0)).to be == true
    end
  end

  module DecodeHelpers
    def validate(e)
      insist { e.is_a?(LogStash::Event) }
      send("validate_ecs_#{ecs_compatibility}", e)
    end

    def validate_ecs_v1(e)
      insist { e.get('[cef][version]') } == "0"
      insist { e.get('[observer][version]') } == "1.0"
      insist { e.get('[event][code]') } == "100"
      insist { e.get('[cef][name]') } == "trojan successfully stopped"
      insist { e.get('[event][severity]') } == "10"
    end

    def validate_ecs_disabled(e)
      insist { e.get('cefVersion') } == "0"
      insist { e.get('deviceVersion') } == "1.0"
      insist { e.get('deviceEventClassId') } == "100"
      insist { e.get('name') } == "trojan successfully stopped"
      insist { e.get('severity') } == "10"
    end

    ##
    # Use the given codec to decode the given data, ensuring exactly one event is emitted.
    #
    # If a block is given, yield the resulting event to the block _outside_ of `LogStash::Codecs::CEF#decode(String)`
    # in order to avoid mismatched-exceptions raised by RSpec triggering the codec's exception-handling.
    #
    # @param codec [#decode]
    # @param data [String]
    # @yieldparam event [Event]
    # @yieldreturn [void]
    # @return [Event]
    def decode_one(codec, data)
      events = do_decode(codec, data)
      fail("Expected one event, got #{events.size} events: #{events.inspect}") unless events.size == 1
      event = events.first

      if block_given?
        aggregate_failures('decode one') do
          yield event
        end
      end

      event
    end

    ##
    # Use the given codec to decode the given data, returning an Array of the resulting Events
    #
    # If a block is given, each event is yielded to the block _outside_ of `LogStash::Codecs::CEF#decode(String)`
    # in order to avoid mismatched-exceptions raised by RSpec triggering the codec's exception-handling.
    #
    # @param codec [#decode]
    # @param data [String]
    # @yieldparam event [Event]
    # @yieldreturn [void]
    # @return [Array<Event>]
    def do_decode(codec, data)
      events = []
      codec.decode(data) do |event|
        events << event
      end

      events.each { |event| yield event } if block_given?

      events
    end
  end

  context "#decode", :ecs_compatibility_support do
    ecs_compatibility_matrix(:disabled,:v1) do |ecs_select|
      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      let (:message) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }

      include DecodeHelpers

      context "with delimiter set" do
        # '\r\n' in single quotes to simulate the real input from a config
        # containing \r\n as 4-character sequence in the config:
        #
        #   delimiter => "\r\n"
        #
        # Related: https://github.com/elastic/logstash/issues/1645
        subject(:codec) { LogStash::Codecs::CEF.new("delimiter" => '\r\n') }

        it "should parse on the delimiter " do
          do_decode(subject,message) do |e|
            raise Exception.new("Should not get here. If we do, it means the decoder emitted an event before the delimiter was seen?")
          end

          decode_one(subject, "\r\n") do |e|
            validate(e)
            insist { e.get(ecs_select[disabled: "deviceVendor", v1:"[observer][vendor]"]) } == "security"
            insist { e.get(ecs_select[disabled: "deviceProduct", v1:"[observer][product]"]) } == "threatmanager"
          end
        end
      end

      context 'when a CEF header ends with a pair of properly-escaped backslashes' do
        let(:backslash) { '\\' }
        let(:pipe) { '|' }
        let(:message) { "CEF:0|security|threatmanager|1.0|100|double backslash" +
                        backslash + backslash + # escaped backslash
                        backslash + backslash + # escaped backslash
                        "|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }

        it 'should include the backslashes unescaped' do
          event = decode_one(subject, message)

          expect(event.get(ecs_select[disabled:'name',    v1:'[cef][name]'])).to eq('double backslash' + backslash + backslash )
          expect(event.get(ecs_select[disabled:'severity',v1:'[event][severity]'])).to eq('10') # ensure we didn't consume the separator
        end
      end

      it "should parse the cef headers" do
        decode_one(subject, message) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"deviceVendor", v1:"[observer][vendor]"]) } == "security"
          insist { e.get(ecs_select[disabled:"deviceProduct",v1:"[observer][product]"]) } == "threatmanager"
        end
      end

      it "should parse the cef body" do
        decode_one(subject, message) do |e|
          insist { e.get(ecs_select[disabled:"sourceAddress",     v1:"[source][ip]"])} == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get(ecs_select[disabled:"sourcePort",        v1:"[source][port]"]) } == "1232"
        end
      end

      let (:missing_headers) { "CEF:0|||1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
      it "should be OK with missing CEF headers (multiple pipes in sequence)" do
        decode_one(subject, missing_headers) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"deviceVendor", v1:"[observer][vendor]"]) } == ""
          insist { e.get(ecs_select[disabled:"deviceProduct",v1:"[observer][product]"]) } == ""
        end
      end

      let (:leading_whitespace) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192 dst=12.121.122.82 spt=1232" }
      it "should strip leading whitespace from the message" do
        decode_one(subject, leading_whitespace) do |e|
          validate(e)
        end
      end

      let (:escaped_pipes) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this\|has an escaped pipe' }
      it "should be OK with escaped pipes in the message" do
        decode_one(subject, escaped_pipes) do |e|
          insist { e.get("moo") } == 'this\|has an escaped pipe'
        end
      end

      let (:pipes_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this|has an pipe'}
      it "should be OK with not escaped pipes in the message" do
        decode_one(subject, pipes_in_message) do |e|
          insist { e.get("moo") } == 'this|has an pipe'
        end
      end

      # while we may see these in practice, equals MUST be escaped in the extensions per the spec.
      let (:equal_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this =has = equals\='}
      it "should be OK with equal in the message" do
        decode_one(subject, equal_in_message) do |e|
          insist { e.get("moo") } == 'this =has = equals='
        end
      end

      context "zoneless deviceReceiptTime(rt) when deviceTimeZone(dtz) is provided" do
        let(:cef_formatted_timestamp) { 'Jul 19 2017 10:50:21.127' }
        let(:zone_name) { 'Europe/Moscow' }

        let(:utc_timestamp) { Time.iso8601("2017-07-19T07:50:21.127Z") } # In summer of 2017, Europe/Moscow was UTC+03:00

        let(:destination_time_zoned) { %Q{CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|Very-High| eventId=1 msg=Worm successfully stopped art=1500464384997 deviceSeverity=10 rt=#{cef_formatted_timestamp} src=10.0.0.1 sourceZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 10.0.0.0-10.255.255.255 spt=1232 dst=2.1.2.2 destinationZoneURI=/All Zones/ArcSight System/Public Address Space Zones/RIPE NCC/2.0.0.0-2.255.255.255 (RIPE NCC) ahost=connector.rhel72 agt=192.168.231.129 agentZoneURI=/All Zones/ArcSight System/Private Address Space Zones/RFC1918: 192.168.0.0-192.168.255.255 amac=00-0C-29-51-8A-84 av=7.6.0.8009.0 atz=Europe/Lisbon at=syslog_file dvchost=client1 dtz=#{zone_name} _cefVer=0.1 aid=3UBajWl0BABCABBzZSlmUdw==} }

        if ecs_select.active_mode == :disabled
          it 'persists deviceReceiptTime and deviceTimeZone verbatim' do
            decode_one(subject, destination_time_zoned) do |event|
              expect(event.get('deviceReceiptTime')).to eq("Jul 19 2017 10:50:21.127")
              expect(event.get('deviceTimeZone')).to eq('Europe/Moscow')
            end
          end
        else
          it 'sets the @timestamp using the value in `rt` combined with the offset provided by `dtz`' do
            decode_one(subject, destination_time_zoned) do |event|
              expected_time = LogStash::Timestamp.new(utc_timestamp)
              expect(event.get('[@timestamp]').to_s).to eq(expected_time.to_s)
              expect(event.get('[event][timezone]')).to eq(zone_name)
            end
          end
        end
      end

      let(:malformed_unescaped_equals_in_extension_value) { %q{CEF:0|FooBar|Web Gateway|1.2.3.45.67|200|Success|2|rt=Sep 07 2018 14:50:39 cat=Access Log dst=1.1.1.1 dhost=foo.example.com suser=redacted src=2.2.2.2 requestMethod=POST request='https://foo.example.com/bar/bingo/1' requestClientApplication='Foo-Bar/2018.1.7; Email:user@example.com; Guid:test=' cs1= cs1Label=Foo Bar} }
      it 'should split correctly' do
        decode_one(subject, malformed_unescaped_equals_in_extension_value) do |event|
          expect(event.get(ecs_select[disabled:"cefVersion",        v1:"[cef][version]"])).to eq('0')
          expect(event.get(ecs_select[disabled:"deviceVendor",      v1:"[observer][vendor]"])).to eq('FooBar')
          expect(event.get(ecs_select[disabled:"deviceProduct",     v1:"[observer][product]"])).to eq('Web Gateway')
          expect(event.get(ecs_select[disabled:"deviceVersion",     v1:"[observer][version]"])).to eq('1.2.3.45.67')
          expect(event.get(ecs_select[disabled:"deviceEventClassId",v1:"[event][code]"])).to eq('200')
          expect(event.get(ecs_select[disabled:"name",              v1:"[cef][name]"])).to eq('Success')
          expect(event.get(ecs_select[disabled:"severity",          v1:"[event][severity]"])).to eq('2')

          # extension key/value pairs
          if ecs_compatibility == :disabled
            expect(event.get('deviceReceiptTime')).to eq('Sep 07 2018 14:50:39')
          else
            expected_time = LogStash::Timestamp.new(Time.parse('Sep 07 2018 14:50:39')).to_s
            expect(event.get('[@timestamp]').to_s).to eq(expected_time)
          end
          expect(event.get(ecs_select[disabled:'deviceEventCategory',     v1:'[cef][category]'])).to eq('Access Log')
          expect(event.get(ecs_select[disabled:'deviceVersion',           v1:'[observer][version]'])).to eq('1.2.3.45.67')
          expect(event.get(ecs_select[disabled:'destinationAddress',      v1:'[destination][ip]'])).to eq('1.1.1.1')
          expect(event.get(ecs_select[disabled:'destinationHostName',     v1:'[destination][domain]'])).to eq('foo.example.com')
          expect(event.get(ecs_select[disabled:'sourceUserName',          v1:'[source][user][name]'])).to eq('redacted')
          expect(event.get(ecs_select[disabled:'sourceAddress',           v1:'[source][ip]'])).to eq('2.2.2.2')
          expect(event.get(ecs_select[disabled:'requestMethod',           v1:'[http][request][method]'])).to eq('POST')
          expect(event.get(ecs_select[disabled:'requestUrl',              v1:'[url][original]'])).to eq(%q{'https://foo.example.com/bar/bingo/1'})
          # Although the value for `requestClientApplication` contains an illegal unquoted equals sign, the sequence
          # preceeding the unescaped-equals isn't shaped like a key, so we allow it to be a part of the value.
          expect(event.get(ecs_select[disabled:'requestClientApplication',v1:'[user_agent][original]'])).to eq(%q{'Foo-Bar/2018.1.7; Email:user@example.com; Guid:test='})
          expect(event.get(ecs_select[disabled:'deviceCustomString1Label',v1:'[cef][device_custom_string_1][label]'])).to eq('Foo Bar')
          expect(event.get(ecs_select[disabled:'deviceCustomString1',     v1:'[cef][device_custom_string_1][value]'])).to eq('')
        end
      end

      context('escaped-equals and unescaped-spaces in the extension values') do
        let(:query_string) { 'key1=value1&key2=value3 aa.bc&key3=value4'}
        let(:escaped_query_string) { query_string.gsub('=','\\=') }
        let(:cef_message) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|go=start now query_string=#{escaped_query_string} final=done" }

        it 'captures the extension values correctly' do
          event = decode_one(subject, cef_message)

          expect(event.get('go')).to eq('start now')
          expect(event.get('query_string')).to eq(query_string)
          expect(event.get('final')).to eq('done')
        end
      end

      let (:escaped_backslash_in_header) {'CEF:0|secu\\\\rity|threat\\\\manager|1.\\\\0|10\\\\0|tro\\\\jan successfully stopped|\\\\10|'}
      it "should be OK with escaped backslash in the headers" do
        decode_one(subject, escaped_backslash_in_header) do |e|
          insist { e.get(ecs_select[disabled:"cefVersion",        v1:"[cef][version]"]) } == '0'
          insist { e.get(ecs_select[disabled:"deviceVendor",      v1:"[observer][vendor]"]) } == 'secu\\rity'
          insist { e.get(ecs_select[disabled:"deviceProduct",     v1:"[observer][product]"]) } == 'threat\\manager'
          insist { e.get(ecs_select[disabled:"deviceVersion",     v1:"[observer][version]"]) } == '1.\\0'
          insist { e.get(ecs_select[disabled:"deviceEventClassId",v1:"[event][code]"]) } == '10\\0'
          insist { e.get(ecs_select[disabled:"name",              v1:"[cef][name]"]) } == 'tro\\jan successfully stopped'
          insist { e.get(ecs_select[disabled:"severity",          v1:"[event][severity]"]) } == '\\10'
        end
      end

      let (:escaped_backslash_in_header_edge_case) {'CEF:0|security\\\\\\||threatmanager\\\\|1.0|100|trojan successfully stopped|10|'}
      it "should be OK with escaped backslash in the headers (edge case: escaped slash in front of pipe)" do
        decode_one(subject, escaped_backslash_in_header_edge_case) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"deviceVendor", v1:"[observer][vendor]"]) } == 'security\\|'
          insist { e.get(ecs_select[disabled:"deviceProduct",v1:"[observer][product]"]) } == 'threatmanager\\'
        end
      end

      let (:escaped_pipes_in_header) {'CEF:0|secu\\|rity|threatmanager\\||1.\\|0|10\\|0|tro\\|jan successfully stopped|\\|10|'}
      it "should be OK with escaped pipes in the headers" do
        decode_one(subject, escaped_pipes_in_header) do |e|
          insist { e.get(ecs_select[disabled:"cefVersion",        v1:"[cef][version]"]) } == '0'
          insist { e.get(ecs_select[disabled:"deviceVendor",      v1:"[observer][vendor]"]) } == 'secu|rity'
          insist { e.get(ecs_select[disabled:"deviceProduct",     v1:"[observer][product]"]) } == 'threatmanager|'
          insist { e.get(ecs_select[disabled:"deviceVersion",     v1:"[observer][version]"]) } == '1.|0'
          insist { e.get(ecs_select[disabled:"deviceEventClassId",v1:"[event][code]"]) } == '10|0'
          insist { e.get(ecs_select[disabled:"name",              v1:"[cef][name]"]) } == 'tro|jan successfully stopped'
          insist { e.get(ecs_select[disabled:"severity",          v1:"[event][severity]"]) } == '|10'
        end
      end

      let (:backslash_in_message) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|moo=this \\has \\ backslashs\\'}
      it "should be OK with backslashs in the message" do
        decode_one(subject, backslash_in_message) do |e|
          insist { e.get("moo") } == 'this \\has \\ backslashs\\'
        end
      end

      let (:equal_in_header) {'CEF:0|security|threatmanager=equal|1.0|100|trojan successfully stopped|10|'}
      it "should be OK with equal in the headers" do
        decode_one(subject, equal_in_header) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"deviceProduct",v1:"[observer][product]"]) } == "threatmanager=equal"
        end
      end

      let (:spaces_in_between_keys) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10| src=10.0.0.192  dst=12.121.122.82  spt=1232'}
      it "should be OK to have one or more spaces between keys" do
        decode_one(subject, spaces_in_between_keys) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get(ecs_select[disabled:"sourcePort",v1:"[source][port]"]) } == "1232"
        end
      end

      let (:dots_in_keys) {'CEF:0|Vendor|Device|Version|13|my message|5|dvchost=loghost cat=traffic deviceSeverity=notice ad.nn=TEST src=192.168.0.1 destinationPort=53'}
      it "should be OK with dots in keys" do
        decode_one(subject, dots_in_keys) do |e|
          insist { e.get(ecs_select[disabled:"deviceHostName",v1:"[observer][hostname]"]) } == "loghost"
          insist { e.get("ad.nn") } == 'TEST'
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == '192.168.0.1'
          insist { e.get(ecs_select[disabled:"destinationPort",v1:"[destination][port]"]) } == '53'
        end
      end

      let (:allow_spaces_in_values) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82  spt=1232 dproc=InternetExplorer x.x.x.x'}
      it "should be OK to have one or more spaces in values" do
        decode_one(subject, allow_spaces_in_values) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get(ecs_select[disabled:"sourcePort",v1:"[source][port]"]) } == "1232"
          insist { e.get(ecs_select[disabled:"destinationProcessName",v1:"[destination][process][name]"]) } == "InternetExplorer x.x.x.x"
        end
      end

      let (:preserve_additional_fields_with_dot_notations) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 additional.dotfieldName=new_value ad.Authentification=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 ad.Error_,Code=3221225578 dst=12.121.122.82 ad.field[0]=field0 ad.name[1]=new_name'}
      it "should keep ad.fields" do
        decode_one(subject, preserve_additional_fields_with_dot_notations) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get("[ad.field][0]") } == "field0"
          insist { e.get("[ad.name][1]") } == "new_name"
          insist { e.get("ad.Authentification") } == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
          insist { e.get('ad.Error_,Code') } == "3221225578"
          insist { e.get("additional.dotfieldName") } == "new_value"
        end
      end

      let(:preserve_complex_multiple_dot_notation_in_extension_fields) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 additional.dotfieldName=new_value ad.Authentification=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 ad.Error_,Code=3221225578 dst=12.121.122.82 ad.field[0]=field0 ad.foo.name[1]=new_name' }
      it "should keep ad.fields" do
        decode_one(subject, preserve_complex_multiple_dot_notation_in_extension_fields) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get("[ad.field][0]") } == "field0"
          insist { e.get("[ad.foo.name][1]") } == "new_name"
          insist { e.get("ad.Authentification") } == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
          insist { e.get('ad.Error_,Code') } == "3221225578"
          insist { e.get("additional.dotfieldName") } == "new_value"
        end
      end

      let (:preserve_random_values_key_value_pairs_alongside_with_additional_fields) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 cs4=401 random.user Admin 0 23041A10181C0000  23041810181C0000  /CN\=random.user/OU\=User Login End-Entity  /CN\=TEST/OU\=Login CA TEST 34 additional.dotfieldName=new_value ad.Authentification=MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 ad.Error_,Code=3221225578 dst=12.121.122.82 ad.field[0]=field0 ad.name[1]=new_name'}
      it "should correctly parse random values even with additional fields in message" do
        decode_one(subject, preserve_random_values_key_value_pairs_alongside_with_additional_fields) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get("[ad.field][0]") } == "field0"
          insist { e.get("[ad.name][1]") } == "new_name"
          insist { e.get("ad.Authentification") } == "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0"
          insist { e.get("ad.Error_,Code") } == "3221225578"
          insist { e.get("additional.dotfieldName") } == "new_value"
          insist { e.get(ecs_select[disabled:"deviceCustomString4",v1:"[cef][device_custom_string_4][value]"]) } == "401 random.user Admin 0 23041A10181C0000  23041810181C0000  /CN\=random.user/OU\=User Login End-Entity  /CN\=TEST/OU\=Login CA TEST 34"
        end
      end

      let (:preserve_unmatched_key_mappings) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 new_key_by_device=new_values here'}
      it "should preserve unmatched key mappings" do
        decode_one(subject, preserve_unmatched_key_mappings) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress",v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get("new_key_by_device") } == "new_values here"
        end
      end

      let (:translate_abbreviated_cef_fields) {'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 proto=TCP shost=source.host.name dhost=destination.host.name spt=11024 dpt=9200 outcome=Success amac=00:80:48:1c:24:91'}
      it "should translate most known abbreviated CEF field names" do
        decode_one(subject, translate_abbreviated_cef_fields) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"sourceAddress",      v1:"[source][ip]"]) } == "10.0.0.192"
          insist { e.get(ecs_select[disabled:"destinationAddress", v1:"[destination][ip]"]) } == "12.121.122.82"
          insist { e.get(ecs_select[disabled:"transportProtocol",  v1:"[network][transport]"]) } == "TCP"
          insist { e.get(ecs_select[disabled:"sourceHostName",     v1:"[source][domain]"]) } == "source.host.name"
          insist { e.get(ecs_select[disabled:"destinationHostName",v1:"[destination][domain]"]) } == "destination.host.name"
          insist { e.get(ecs_select[disabled:"sourcePort",         v1:"[source][port]"]) } == "11024"
          insist { e.get(ecs_select[disabled:"destinationPort",    v1:"[destination][port]"]) } == "9200"
          insist { e.get(ecs_select[disabled:"eventOutcome",       v1:"[event][outcome]"]) } == "Success"
          insist { e.get(ecs_select[disabled:"agentMacAddress",    v1:"[agent][mac]"])} == "00:80:48:1c:24:91"
        end
      end

      let (:syslog) { "Syslogdate Sysloghost CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=10.0.0.192 dst=12.121.122.82 spt=1232" }
      it "Should detect headers before CEF starts" do
        decode_one(subject, syslog) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:'syslog',v1:'[log][syslog][header]']) } == 'Syslogdate Sysloghost'
        end
      end

      let(:log_with_fileHash) { "Syslogdate Sysloghost CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|fileHash=1bad1dea" }
      it 'decodes fileHash to [file][hash]' do
        decode_one(subject, log_with_fileHash) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled:"fileHash", v1:"[file][hash]"]) } == "1bad1dea"
        end
      end

      let(:log_with_custom_typed_fields) { "Syslogdate Sysloghost CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|cfp15=3.1415926 cfp15Label=pi c6a12=::1 c6a12Label=localhost cn7=8191 cn7Label=mersenne cs4=silly cs4Label=theory" }
      it 'decodes to mapped numbered fields' do
        decode_one(subject, log_with_custom_typed_fields) do |e|
          validate(e)
          insist { e.get(ecs_select[disabled: "deviceCustomFloatingPoint15",      v1: "[cef][device_custom_floating_point_15][value]"]) } == "3.1415926"
          insist { e.get(ecs_select[disabled: "deviceCustomFloatingPoint15Label", v1: "[cef][device_custom_floating_point_15][label]"]) } == "pi"
          insist { e.get(ecs_select[disabled: "deviceCustomIPv6Address12",        v1: "[cef][device_custom_ipv6_address_12][value]"]) } == "::1"
          insist { e.get(ecs_select[disabled: "deviceCustomIPv6Address12Label",   v1: "[cef][device_custom_ipv6_address_12][label]"]) } == "localhost"
          insist { e.get(ecs_select[disabled: "deviceCustomNumber7",              v1: "[cef][device_custom_number_7][value]"]) } == "8191"
          insist { e.get(ecs_select[disabled: "deviceCustomNumber7Label",         v1: "[cef][device_custom_number_7][label]"]) } == "mersenne"
          insist { e.get(ecs_select[disabled: "deviceCustomString4",              v1: "[cef][device_custom_string_4][value]"]) } == "silly"
          insist { e.get(ecs_select[disabled: "deviceCustomString4Label",         v1: "[cef][device_custom_string_4][label]"]) } == "theory"
        end
      end

      context 'with UTF-8 message' do
        let(:message) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=192.168.1.11 target=aaaaaああああaaaa msg=Description Omitted' }

        # since this spec is encoded UTF-8, the literal strings it contains are encoded with UTF-8,
        # but codecs in Logstash tend to receive their input as BINARY (or: ASCII-8BIT); ensure that
        # we can handle either without losing the UTF-8 characters from the higher planes.
        %w(
          BINARY
          UTF-8
        ).each do |external_encoding|
          context "externally encoded as #{external_encoding}" do
            let(:message) { super().force_encoding(external_encoding) }
            it 'should keep the higher-plane characters' do
              decode_one(subject, message.dup) do |event|
                validate(event)
                insist { event.get("target") } == "aaaaaああああaaaa"
                insist { event.get("target").encoding } == Encoding::UTF_8
              end
            end
          end
        end
      end

      context 'non-UTF-8 message' do
        let(:logger_stub) { double('Logger').as_null_object }
        before(:each) do
          allow_any_instance_of(described_class).to receive(:logger).and_return(logger_stub)
        end
        let(:message) { 'CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|src=192.168.1.11 target=aaaaaああああaaaa msg=Description Omitted'.encode('SHIFT_JIS') }
        it 'should emit message unparsed with _cefparsefailure tag' do
          decode_one(subject, message.dup) do |event|
            insist { event.get("message").bytes.to_a } == message.bytes.to_a
            insist { event.get("tags") } == ['_cefparsefailure']
          end
          expect(logger_stub).to have_received(:error).with(/Failed to decode CEF payload/, any_args)
        end
      end

      context "with raw_data_field set" do
        subject(:codec) { LogStash::Codecs::CEF.new("raw_data_field" => "message_raw") }

        it "should return the raw message in field message_raw" do
          decode_one(subject, message.dup) do |e|
            validate(e)
            insist { e.get("message_raw") } == message
          end
        end
      end

      context "legacy aliases" do
        let(:cef_line) { "CEF:0|security|threatmanager|1.0|100|target acquired|10|destinationLongitude=-73.614830 destinationLatitude=45.505918 sourceLongitude=45.4628328 sourceLatitude=9.1076927" }

        it ecs_select[disabled:"creates the fields as provided",v1:"maps to ECS fields"] do
          decode_one(codec, cef_line.dup) do |event|
            #                           |---- LEGACY: AS-PROVIDED ----| |--------- ECS: MAP TO FIELD ----------|
            expect(event.get(ecs_select[disabled:'destinationLongitude',v1:'[destination][geo][location][lon]'])).to eq('-73.614830')
            expect(event.get(ecs_select[disabled:'destinationLatitude', v1:'[destination][geo][location][lat]'])).to eq('45.505918')
            expect(event.get(ecs_select[disabled:'sourceLongitude',     v1:'[source][geo][location][lon]'     ])).to eq('45.4628328')
            expect(event.get(ecs_select[disabled:'sourceLatitude',      v1:'[source][geo][location][lat]'     ])).to eq('9.1076927')
          end
        end
      end
    end
  end

  context "encode and decode", :ecs_compatibility_support do
    subject(:codec) { LogStash::Codecs::CEF.new }

    let(:results)   { [] }

    ecs_compatibility_matrix(:disabled, :v1, :v8 => :v1) do |ecs_select|
      before(:each) do
        allow_any_instance_of(described_class).to receive(:ecs_compatibility).and_return(ecs_compatibility)
      end

      let(:vendor_field)    { ecs_select[disabled:'deviceVendor',       v1:'[observer][vendor]'] }
      let(:product_field)   { ecs_select[disabled:'deviceProduct',      v1:'[observer][product]']}
      let(:version_field)   { ecs_select[disabled:'deviceVersion',      v1:'[observer][version]']}
      let(:signature_field) { ecs_select[disabled:'deviceEventClassId', v1:'[event][code]']}
      let(:name_field)      { ecs_select[disabled:'name',               v1:'[cef][name]']}
      let(:severity_field)  { ecs_select[disabled:'severity',           v1:'[event][severity]']}

      let(:source_dns_domain_field) { ecs_select[disabled:'sourceDnsDomain',v1:'[source][registered_domain]'] }

      it "should return an equal event if encoded and decoded again" do
        codec.on_event{|data, newdata| results << newdata}
        codec.vendor = "%{" + vendor_field + "}"
        codec.product = "%{" + product_field + "}"
        codec.version = "%{" + version_field + "}"
        codec.signature = "%{" + signature_field + "}"
        codec.name = "%{" + name_field + "}"
        codec.severity = "%{" + severity_field + "}"
        codec.fields = [ "foo", source_dns_domain_field ]
        event = LogStash::Event.new.tap do |e|
          e.set(vendor_field, "vendor")
          e.set(product_field, "product")
          e.set(version_field, "2.0")
          e.set(signature_field, "signature")
          e.set(name_field, "name")
          e.set(severity_field, "1")
          e.set("foo", "bar")
          e.set(source_dns_domain_field, "apple")
        end
        codec.encode(event)
        codec.decode(results.first) do |e|
          expect(e.get(vendor_field)).to be == event.get(vendor_field)
          expect(e.get(product_field)).to be == event.get(product_field)
          expect(e.get(version_field)).to be == event.get(version_field)
          expect(e.get(signature_field)).to be == event.get(signature_field)
          expect(e.get(name_field)).to be == event.get(name_field)
          expect(e.get(severity_field)).to be == event.get(severity_field)
          expect(e.get('foo')).to be == event.get('foo')
          expect(e.get(source_dns_domain_field)).to be == event.get(source_dns_domain_field)
        end
      end
    end
  end

end
