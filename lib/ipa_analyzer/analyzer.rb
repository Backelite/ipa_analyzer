require 'tempfile'
require 'zip'
require 'zip/filesystem'
require 'cfpropertylist'
require 'pathname'

module IpaAnalyzer
  class Analyzer
    def initialize(ipa_path)
      @ipa_path = ipa_path
      @ipa_zipfile = nil
      @app_folder_path = nil
    end

    def open!
      begin
        @ipa_zipfile = Zip::File.open(@ipa_path)
        @app_folder_path = find_app_folder_in_ipa
      rescue => e
        raise 'File is not a valid IPA'
      end
      raise 'No app folder found in the IPA' if @app_folder_path.nil?
    end

    def open?
      !@ipa_zipfile.nil?
    end

    def close
      @ipa_zipfile.close if open?
    end

    def cert_extract_issuer_parameterized(subject, param)
      # The following regex was previously used to match fields when not 
      # using '-nameopt -esc_msb,utf8'' switch with openssl
      # match = %r{\/#{Regexp.quote(param)}=([^\/]*)}.match(subject) 

      match = /#{Regexp.quote(param)}=([^=]*)(, [A-Z]+=|$)/.match(subject)
      raise "Could not retrieve field '#{param}' from certificate info" if match.nil? || match.captures.nil? || match.captures.empty?
      match.captures[0]
    end

    def cert_extract_issuer(data_as_hex, result)
      subject = `echo #{data_as_hex} | xxd -r -p | openssl x509 -inform DER -noout -subject -nameopt -esc_msb,utf8`
      begin
        result[:issuer_raw] = subject
        result[:cn] = cert_extract_issuer_parameterized(subject, 'CN')
        result[:uid] = cert_extract_issuer_parameterized(subject, 'UID')
        result[:org] = cert_extract_issuer_parameterized(subject, 'O')
      rescue => e
        result[:error_msg] = "#{e.message}. Please check the openssl version installed on your system"
      end
    end

    def cert_extract_date(date_str)
      match = /=(.*)$/.match(date_str)
      raise "Could not retrieve date from certificate info" if match.nil? || match.captures.nil? || match.captures.empty?
      match.captures[0]
    end

    def cert_extract_dates(data_as_hex, result)
      start_date = `echo #{data_as_hex} | xxd -r -p | openssl x509 -inform DER -noout -startdate`
      end_date = `echo #{data_as_hex} | xxd -r -p | openssl x509 -inform DER -noout -enddate`

      begin
        result[:expiration_date] = cert_extract_date(start_date)
        result[:creation_date] = cert_extract_date(end_date)
      rescue => e
        result[:error_msg] = "#{e.message}. Please check the openssl version installed on your system"
      end
    end

    def collect_cert_info(base64data)
      result = {
        issuer_raw: nil,
        cn: nil,
        uid: nil,
        org: nil,
        expiration_date: nil,
        creation_date: nil
      }
      data_as_hex = base64data.first.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
      cert_extract_issuer(data_as_hex, result)
      cert_extract_dates(data_as_hex, result)
      result
    end

    def collect_provision_info
      collect_provision_info_with_path("#{@app_folder_path}/")
    end

    def collect_provision_info_with_path(path)
      raise 'IPA is not open' unless open?

      result = {
        path_in_ipa: nil,
        content: {}
      }
      mobileprovision_path = "#{path}embedded.mobileprovision"
      mobileprovision_entry = @ipa_zipfile.find_entry(mobileprovision_path)

      raise "Embedded mobile provisioning file not found in (#{@ipa_path}) at path (#{mobileprovision_path})" unless mobileprovision_entry
      result[:path_in_ipa] = mobileprovision_entry.to_s

      tempfile = Tempfile.new(::File.basename(mobileprovision_entry.name))
      begin
        @ipa_zipfile.extract(mobileprovision_entry, tempfile.path) { override = true }
        # 2> /dev/null redirects openssl second output stream to somewhere else so we dont get it in the main output stream
        plist_as_xml = `openssl smime -inform der -verify -noverify -in #{tempfile.path} 2> /dev/null`
        data = CFPropertyList::List.new(data: plist_as_xml)
        plist = CFPropertyList.native_types(data.value)
        plist.each do |key, value|
          if key == 'DeveloperCertificates'
            result[:content][:cert_info] = collect_cert_info(value)
            next
          end
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
      collect_info_plist_info_with_path("#{@app_folder_path}/Info.plist")
    end

    def collect_info_plist_info_with_path(path)
      raise 'IPA is not open' unless open?

      result = {
        path_in_ipa: nil,
        content: {}
      }
      info_plist_entry = @ipa_zipfile.find_entry(path)
      raise "File 'Info.plist' not found in #{@ipa_path}" unless info_plist_entry

      result[:path_in_ipa] = info_plist_entry.to_s
      tempfile = Tempfile.new(::File.basename(info_plist_entry.name))
      begin
        @ipa_zipfile.extract(info_plist_entry, tempfile.path) { override = true }
        # convert from binary Plist to XML Plist
        plist_object = CFPropertyList::List.new(file: tempfile.path)
        plist = CFPropertyList.native_types(plist_object.value)
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
          content: collect_info_plist_info_with_path(fwk_infoplist_filename)[:content]
        }
        result[:content].push(fwk_info)
      end
      result
    end

    def collect_entitlements_info
      collect_entitlements_info_with_path("#{@app_folder_path}/")
    end

    # List the contents of the entitlements file included by the package (if any)
    def collect_entitlements_info_with_path(path)
      raise 'IPA is not open' unless open?

      fwk_name = Pathname(path).split.last.to_s.split('.')[0]
      result = nil

      possible_ent_files = [
        "#{path}Entitlements.plist",
        "#{path}archived-expanded-entitlements.xcent"
      ]

      possible_ent_files.push("#{path}#{fwk_name}.entitlements") unless fwk_name.nil?

      result = nil
      possible_ent_files.each do |ent_file|
        next if !result.nil? || @ipa_zipfile.find_entry(ent_file).nil?
        result = collect_info_plist_info_with_path(ent_file)
      end

      # Default to error message if no entitlements were found
      result = { :content =>  { "error" => "Could not find an entitlements file" } } if result.nil?

      result
    end

    # Retrieve info from Watch extension (if any)
    def collect_watch_info
      list = collect_app_extensions_info_from_path("#{@app_folder_path}/Watch/", '.app')
      list ? list.first : nil
    end

    # Recursive function that collects Info.plist, mobileprovision and entitlements
    # Recurses on plugins
    def collect_app_extensions_info_from_path(path, extension)
      raise 'IPA is not open' unless open?

      search_path = "#{path}*#{extension}"
      watch_entries = @ipa_zipfile.glob(search_path)

      return nil if watch_entries.nil? || watch_entries.length.zero?

      result_list = []
      watch_entries.each do |fwk|
        result = {
          path_in_ipa: fwk.name,
          mobileprovision: {},
          entitlements: {},
          info_plist: {},
          plugins: []
        }
        result[:info_plist] = collect_info_plist_info_with_path("#{fwk.name}Info.plist")[:content]
        result[:mobileprovision] = collect_provision_info_with_path(fwk.name)[:content]
        watch_ext_entitlements_info = collect_entitlements_info_with_path(fwk.name)
        result[:entitlements] = watch_ext_entitlements_info[:content] unless watch_ext_entitlements_info.nil?
        plugins = collect_app_extensions_info_from_path("#{fwk.name}PlugIns/", '.appex')
        result[:plugins].concat(plugins) if !plugins.nil?
        result_list.push(result)
      end

      result_list
    end

    # Detail elements of the App Extensions included by the package (if any)
    def collect_app_extensions_info
      collect_app_extensions_info_from_path("#{@app_folder_path}/PlugIns/", '.appex')
    end

    private

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
