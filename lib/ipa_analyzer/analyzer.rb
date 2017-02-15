require 'tempfile'
require 'zip'
require 'zip/filesystem'
require 'plist'
require_relative 'os'

module IpaAnalyzer
  class Analyzer
    def initialize(ipa_path)
      @ipa_path = ipa_path
      @ipa_zipfile = nil
      @app_folder_path = nil
    end

    def open!
      @ipa_zipfile = Zip::File.open(@ipa_path)
      @app_folder_path = find_app_folder_in_ipa
      raise 'No app folder found in the IPA' if @app_folder_path.nil?
    end

    def open?
      !@ipa_zipfile.nil?
    end

    def close
      @ipa_zipfile.close if open?
    end

    def collect_provision_info
      raise 'IPA is not open' unless open?

      result = {
        path_in_ipa: nil,
        content: {}
      }
      mobileprovision_path = "#{@app_folder_path}/embedded.mobileprovision"
      mobileprovision_entry = @ipa_zipfile.find_entry(mobileprovision_path)

      raise "Embedded mobile provisioning file not found in (#{@ipa_path}) at path (#{mobileprovision_path})" unless mobileprovision_entry
      result[:path_in_ipa] = mobileprovision_entry.to_s

      tempfile = Tempfile.new(::File.basename(mobileprovision_entry.name))
      begin
        @ipa_zipfile.extract(mobileprovision_entry, tempfile.path) { override = true }
        # plist = Plist.parse_xml(`security cms -D -i #{tempfile.path}`)

        # 2> /dev/null redirects openssl second output stream to somewhere else so we dont get it in the main os
        plist = Plist.parse_xml(`openssl smime -inform der -verify -noverify -in #{tempfile.path} 2> /dev/null`)

        plist.each do |key, value|
          next if key == 'DeveloperCertificates'

          parse_value = nil
          parse_value = case value
                        when Hash
                          value
                        when Array
                          value
                        else
                          value.to_s
                        end

          result[:content][key] = parse_value
        end

      rescue => e
        puts e.message
        result = nil
      ensure
        tempfile.close && tempfile.unlink
      end
      result
    end

    def collect_info_plist_info
      collect_info_plist_info_from_file("#{@app_folder_path}/Info.plist")
    end

    def collect_info_plist_info_from_file(filename)
      raise 'IPA is not open' unless open?

      result = {
        path_in_ipa: nil,
        content: {}
      }
      info_plist_entry = @ipa_zipfile.find_entry(filename)

      raise "File 'Info.plist' not found in #{@ipa_path}" unless info_plist_entry
      result[:path_in_ipa] = info_plist_entry.to_s

      tempfile = Tempfile.new(::File.basename(info_plist_entry.name))
      decoded_tmp = Tempfile.new(::File.basename(info_plist_entry.name + '.tmp'))
      begin
        @ipa_zipfile.extract(info_plist_entry, tempfile.path) { override = true }
        # convert from binary Plist to XML Plist
        command_to_execute = nil
        error_message = nil
        if OS.linux?
          command_to_execute = "plistutil -convert xml1 -i '#{tempfile.path}' > #{decoded_tmp.path}"
          error_message = 'plistutil failed to execute. Is plistutil installed on your system? If not use apt-get install libplist-utils'
        elsif OS.macos?
          command_to_execute = "plutil -convert xml1 '#{tempfile.path}'"
        end
        unless system(command_to_execute)
          vputs error_message unless error_message.nil?
          raise 'Failed to convert binary Plist to XML'
        end
        puts "Finish executing plistutil conversion to XML: #{File.read(decoded_tmp.path)}"
        plist = Plist.parse_xml(decoded_tmp.path)
        puts "Parsed XML content: #{plist.inspect}"

        plist.each do |key, value|
          parse_value = nil
          parse_value = case value
                        when Hash
                          value
                        when Array
                          value
                        else
                          value.to_s
                        end

          result[:content][key] = parse_value
        end

      rescue => e
        puts e.message
        result = nil
      ensure
        tempfile.close && tempfile.unlink
      end
      result
    end

    # List the frameworks used by the package
    def collect_frameworks_info
      raise 'IPA is not open' unless open?

      result = {
        path_in_ipa: nil,
        content: []
      }

      frameworks_entries = @ipa_zipfile.glob("#{@app_folder_path}/Frameworks/*.framework")

      return nil if frameworks_entries.nil? || frameworks_entries.length.zero?

      result[:path_in_ipa] = "#{@app_folder_path}/Frameworks"

      frameworks_entries.each do |fwk|
        fwk_infoplist_filename = "#{fwk.name}Info.plist"
        fwk_info = {
          filename: fwk_infoplist_filename,
          content: collect_info_plist_info_from_file(fwk_infoplist_filename)[:content]
        }
        result[:content].push(fwk_info)
      end

      result
    end

    # List the contents of the entitlements file included by the package (if any)
    def collect_entitlements_info
      raise 'IPA is not open' unless open?

      result = nil

      if !@ipa_zipfile.find_entry("#{@app_folder_path}/Entitlements.plist").nil?
        result = collect_info_plist_info_from_file("#{@app_folder_path}/Entitlements.plist")
      elsif !@ipa_zipfile.find_entry("#{@app_folder_path}/archived-expanded-entitlements.xcent").nil?
        result = collect_info_plist_info_from_file("#{@app_folder_path}/archived-expanded-entitlements.xcent")
      else
        vputs 'INFO: No entitlements found'
      end

      result
    end

    private

    #
    # Find the .app folder which contains both the "embedded.mobileprovision"
    #  and "Info.plist" files.
    def find_app_folder_in_ipa
      raise 'IPA is not open' unless open?

      # Check the most common location
      app_folder_in_ipa = "Payload/#{File.basename(@ipa_path, File.extname(@ipa_path))}.app"
      #
      mobileprovision_entry = @ipa_zipfile.find_entry("#{app_folder_in_ipa}/embedded.mobileprovision")
      info_plist_entry = @ipa_zipfile.find_entry("#{app_folder_in_ipa}/Info.plist")
      #
      if !mobileprovision_entry.nil? && !info_plist_entry.nil?
        return app_folder_in_ipa
      end

      # It's somewhere else - let's find it!
      @ipa_zipfile.dir.entries('Payload').each do |dir_entry|
        next unless dir_entry =~ /.app$/
        app_folder_in_ipa = "Payload/#{dir_entry}"
        mobileprovision_entry = @ipa_zipfile.find_entry("#{app_folder_in_ipa}/embedded.mobileprovision")
        info_plist_entry = @ipa_zipfile.find_entry("#{app_folder_in_ipa}/Info.plist")

        break if !mobileprovision_entry.nil? && !info_plist_entry.nil?
      end

      if !mobileprovision_entry.nil? && !info_plist_entry.nil?
        return app_folder_in_ipa
      end
      nil
    end
  end
end
