# frozen_string_literal: true

# We don't use nokogiri because we use an alpine-based docker image
# And adding the required dependencies triples the size of the image
require 'rexml/document'

module TestSummaryBuildkitePlugin
  module Input
    WORKDIR = 'tmp/test-summary'
    DEFAULT_JOB_ID_REGEX = /(?<job_id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/

    def self.create(type:, **options)
      type = type.to_sym
      raise StandardError, "Unknown file type: #{type}" unless TYPES.key?(type)
      TYPES[type].new(options)
    end

    class Base
      attr_reader :label, :artifact_path, :options

      def initialize(label:, artifact_path:, **options)
        @label = label
        @artifact_path = artifact_path
        @options = options
      end

      def failures
        @failures ||= begin
          f = files.map { |filename| filename_to_failures(filename) }.flatten
          f.each(&:strip_colors) if options[:strip_colors]
          f.sort_by(&:summary)
        end
      end

      protected

      def files
        @files ||= begin
          FileUtils.mkpath(WORKDIR)
          Agent.run('artifact', 'download', artifact_path, WORKDIR)
          Dir.glob("#{WORKDIR}/#{artifact_path}")
        rescue Agent::CommandFailed => err
          if fail_on_error
            raise
          else
            Utils.log_error(err)
            []
          end
        end
      end

      def read(filename)
        File.read(filename).force_encoding(encoding)
      end

      def encoding
        @options[:encoding] || 'UTF-8'
      end

      def fail_on_error
        @options[:fail_on_error] || false
      end

      def filename_to_failures(filename)
        file_contents_to_failures(read(filename)).each { |failure| failure.job_id = job_id(filename) }
      end

      def job_id(filename)
        filename.match(job_id_regex)&.named_captures&.fetch('job_id', nil)
      end

      def job_id_regex
        if @options[:job_id_regex]
          r = Regexp.new(@options[:job_id_regex])
          raise 'Job id regex must have a job_id named capture' unless r.names.include?('job_id')
          r
        else
          DEFAULT_JOB_ID_REGEX
        end
      end
    end

    class OneLine < Base
      def file_contents_to_failures(str)
        str.split("\n")[crop.start..crop.end]
          .reject(&:empty?)
          .map { |line| Failure::Unstructured.new(line) }
      end

      private

      def crop
        @crop ||= OpenStruct.new(
          start: options.dig(:crop, :start) || 0,
          end: -1 - (options.dig(:crop, :end) || 0)
        )
      end
    end

    class JUnit < Base
      def file_contents_to_failures(str)
        xml = REXML::Document.new(str)
        xml.elements.enum_for(:each, '//testcase').each_with_object([]) do |testcase, failures|
          testcase.elements.each('failure | error') do |failure|
            failures << Failure::Structured.new(
              summary: summary(failure),
              message: message(failure),
              details: details(failure)
            )
          end
        end
      end

      def summary(failure)
        data = attributes(failure)
        if summary_format
          summary_format % data
        else
          name = data[:'testcase.name']
          file = data[:'testcase.file']
          class_name = data[:'testcase.classname']
          location = if !file.nil? && !file.empty?
                       "#{file}: "
                     elsif !class_name.nil? && !class_name.empty? && class_name != name
                       "#{class_name}: "
                     end
          "#{location}#{name}"
        end
      end

      def attributes(failure)
        # If elements are used in the format string but don't exist in the map, pretend they're blank
        acc = Hash.new('')
        elem = failure
        until elem.parent.nil?
          elem.attributes.each do |attr_name, attr_value|
            acc["#{elem.name}.#{attr_name}".to_sym] = attr_value
          end
          elem = elem.parent
        end
        acc.merge(detail_attributes(failure))
      end

      def detail_attributes(failure)
        matches = details_regex&.match(details(failure))&.named_captures || {}
        # need to symbolize keys
        matches.each_with_object({}) do |(key, value), acc|
          acc[key.to_sym] = value
        end
      end

      def details(failure)
        if options.fetch(:details, true)
          # gets all text elements that are direct children (includes CDATA), and use the unescaped values
          failure.texts.map(&:value).join('').strip
        end
      end

      def message(failure)
        failure.attributes['message']&.to_s if options.fetch(:message, true)
      end

      def summary_format
        @summary_format ||= options.dig(:summary, :format)
      end

      def details_regex
        @details_regex ||= begin
          regex_str = options.dig(:summary, :details_regex)
          Regexp.new(regex_str) if regex_str
        end
      end
    end

    class Tap < Base
      def file_contents_to_failures(tap)
        suite = ::TestSummaryBuildkitePlugin::Tap::Parser.new(tap).parse
        suite.tests.select { |x| !x.passed && !x.todo && !x.skipped }.map do |x|
          Failure::Structured.new(
            summary: x.description,
            details: x.yaml || x.diagnostic
          )
        end
      end
    end

    class Checkstyle < Base
      def file_contents_to_failures(str)
        xml = REXML::Document.new(str)
        xml.elements.enum_for(:each, '//file').flat_map do |file|
          filename = file.attribute('name').value

          file.elements.map do |error|
            Failure::Structured.new(
              summary: summary(filename, error),
              details: error.attribute('source').value
            )
          end
        end
      end

      def summary(filename, error)
        severity = error.attribute('severity')&.value
        line = error.attribute('line')&.value
        column = error.attribute('column')&.value
        location = [filename, line, column].compact.join(':')
        message = error.attribute('message')&.value

        "[#{severity}] #{location}: #{message}"
      end
    end

    class AndroidLint < Base
      def file_contents_to_failures(str)
        xml = REXML::Document.new(str)
        xml.elements.enum_for(:each, '//issue').each_with_object([]) do |issue, array|
          # Skip info (these are usually suppressed from the baseline file)
          unless issue.attribute('severity')&.value == "Information"
            array << Failure::Structured.new(
              summary: summary(issue),
              message: message(issue),
              details: details(issue)
            )
          end
        end
      end

      def summary(issue)
        severity = issue.attribute('severity')&.value
        filename = issue.elements['location'].attribute('file')&.value
        line = issue.elements['location'].attribute('line')&.value
        column = issue.elements['location'].attribute('column')&.value
        location = [filename, line, column].compact.join(':')
        message = issue.attribute('message')&.value

        "[#{severity}] #{location}: #{message}"
      end

      def message(issue)
        issue.attribute('message').value
      end

      def details(issue)
        details = issue.attribute('summary').value.to_s.dup

        unless issue.attribute('errorLine1').nil? || issue.attribute('errorLine2').nil?
          details.concat("

```
#{issue.attribute('errorLine1').value}
#{issue.attribute('errorLine2').value}
```")
        end

        unless issue.attribute('explanation').nil?
          details.concat("

#{issue.attribute('explanation').value}")
        end
      end
    end

    class Pmd < Base
      def file_contents_to_failures(str)
        xml = REXML::Document.new(str)
        xml.elements.enum_for(:each, '//file').flat_map do |file|
          filename = file.attribute('name').value
          file.elements.map do |violation|
            Failure::Structured.new(
              summary: summary(filename, violation),
              message: message(violation),
              details: details(filename, violation)
            )
          end
        end
      end

      private

      def summary(filename, violation)
        severity = priority_to_severity_label(violation.attribute('priority')&.value)
        location = get_location(filename, violation)
        message = message(violation)
        "[#{severity}] #{location}: #{message}"
      end


      def message(violation)
        violation.text.strip
      end

      def details(filename, violation)
        details = ["Rule: #{violation.attribute('rule').value}

File: #{filename}
Package: #{violation.attribute('package').value}"]
        details.push("Class: #{violation.attribute('class').value}") unless violation.attribute('class').nil?
        details.push("Method: #{violation.attribute('method').value}") unless violation.attribute('method').nil?
        details.push("Variable: #{violation.attribute('variable').value}") unless violation.attribute('variable').nil?
        details.push("\n#{violation.text.strip}")
        details.push(violation.attribute('externalInfoUrl').value) unless violation.attribute('externalInfoUrl').nil?
        details.join("\n")
      end

      ##
      # Maps PMD priority integer to a human readable label for annotating.
      # @param priority An integer in `1..5` denoting the priority of the issue.
      # @return A human readable label.
      def priority_to_severity_label(priority)
        case priority
        when '1'
          'Change Required'
        when '2'
          'Change Highly Recommended'
        when '3'
          'Change Recommended'
        when '4'
          'Change Optional'
        when '5'
          'Change Highly Optional'
        else
          'Unknown'
        end
      end

      def get_location(filename, violation)
        line = violation.attribute('beginline')&.value
        column = violation.attribute('begincolumn')&.value
        [filename, line, column].compact.join(':')
      end
    end

    TYPES = {
      oneline: Input::OneLine,
      junit: Input::JUnit,
      tap: Input::Tap,
      checkstyle: Input::Checkstyle,
      androidLint: Input::AndroidLint,
      pmd: Input::Pmd
    }.freeze
  end
end
