# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/cef"
require "logstash/event"

describe LogStash::Codecs::CEF do
  subject do
    next LogStash::Codecs::CEF.new
  end

  context "#encode" do
    subject(:codec) { LogStash::Codecs::CEF.new }

    let(:results)   { [] }

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
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=\{\"ba[rz]\":\"ba[rz] value\",\"ba[rz]\":\"ba[rz] value\"\}$/m)
    end

    it "should encode an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ "bar", "baz" ])
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=\[\"bar\",\"baz\"\]$/m)
    end

    it "should encode a hash in an array value" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => [ { "bar" => "bar value" }, "baz" ])
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=\[\{\"bar\":\"bar value\"\},\"baz\"\]$/m)
    end

    it "should encode a LogStash::Timestamp" do
      codec.on_event{|data, newdata| results << newdata}
      codec.fields = [ "foo" ]
      event = LogStash::Event.new("foo" => LogStash::Timestamp.new)
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|foo=[0-9TZ.:-]+$/m)
    end

    it "should use severity (instead of depricated sev), if severity is set)" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.severity = "5"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|5\|$/m)
    end

    it "should use deprecated sev, if severity is not set (equals default value)" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|4\|$/m)
    end

    it "should use deprecated sev, if severity is explicitly set to default value)" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.severity = "6"
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|4\|$/m)
    end

    it "should use deprecated sev, if severity is invalid" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = "4"
      codec.severity = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|4\|$/m)
    end

    it "should use default value, if severity is not set and sev is invalid" do
      codec.on_event{|data, newdata| results << newdata}
      codec.sev = ""
      codec.fields = []
      event = LogStash::Event.new("foo" => "bar")
      codec.encode(event)
      expect(results.first).to match(/^CEF:0\|Elasticsearch\|Logstash\|1.0\|Logstash\|Logstash\|6\|$/m)
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

    let (:no_ext) { "CEF:0|security|threatmanager|1.0|100|trojan successfully stopped|10|" }
    it "should be OK with no extension dictionary" do
      subject.decode(no_ext) do |e|
        validate(e)
        insist { e["cef_ext"] } == nil
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
