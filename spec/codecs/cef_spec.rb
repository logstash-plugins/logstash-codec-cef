# encoding: utf-8

require "logstash/devutils/rspec/spec_helper"
require "logstash/codecs/cef"
require "logstash/event"

describe LogStash::Codecs::Cef do
  subject do
    next LogStash::Codecs::Cef.new
  end
=begin

  context "#encode" do
    let (:event) {LogStash::Event.new({"message" => "hello world", "host" => "test"})}

    it "should return a default date formatted line" do
      expect(subject).to receive(:on_event).once.and_call_original
      subject.on_event do |e, d|
        insist {d} == event.to_s + "\n"
      end
      subject.encode(event)
    end

    it "should respect the supplied format" do
      format = "%{host}"
      subject.format = format
      expect(subject).to receive(:on_event).once.and_call_original
      subject.on_event do |e, d|
        insist {d} == event.sprintf(format) + "\n"
      end
      subject.encode(event)
    end
  end

  context "#decode" do
    it "should return an event from an ascii string" do
      decoded = false
      subject.decode("hello world\n") do |e|
        decoded = true
        insist { e.is_a?(LogStash::Event) }
        insist { e["message"] } == "hello world"
      end
      insist { decoded } == true
    end

    it "should return an event from a valid utf-8 string" do
      subject.decode("München\n") do |e|
        insist { e.is_a?(LogStash::Event) }
        insist { e["message"] } == "München"
      end
    end
  end

=end
end
