# @summary Structured fact about all managed PKI certificates and private keys

require 'facter'
require 'date'

Facter.add(:vault_certs) do
  confine osfamily: 'RedHat'

  setcode do
    results = {}
    cert_dir = '/etc/pki/vault-secrets'

    Dir["#{cert_dir}/*.json"].each { |filename|
      result = {}
      cert_name = File.basename(filename, ".json")
      cert_file = File.join(cert_dir, "#{cert_name}.pem")
      key_file = File.join(cert_dir, "#{cert_name}.key")
      if File.file?(cert_file) && File.file?(key_file)
        cert_m = Facter::Core::Execution.execute("openssl x509 -in #{cert_file} -noout -modulus", on_fail: nil)
        key_m = Facter::Core::Execution.execute("openssl rsa -in #{key_file} -noout -modulus", on_fail: nil)
        unless cert_m.nil? || key_m.nil?
          cert_modulus = cert_m.strip.split('=')[-1]
          key_modulus = key_m.strip.split('=')[-1]
          result['valid'] = cert_modulus == key_modulus
        end
        cert_dates = Facter::Core::Execution.execute("openssl x509 -in #{cert_file} -noout -dates", on_fail: nil)
        unless cert_dates.nil?
          begin
            expiration = Date.parse(cert_dates.split(%r{\n})[-1].split('=')[-1].strip)
            days_remaining = Integer(expiration - Date.today)
          rescue
            expiration = 'unknown'
            days_remaining = 'unknown'
          end
          result['expiration'] = expiration
          result['days_remaining'] = days_remaining
        end
      else
        result['valid'] = false
      end
      results[cert_name] = result
    }
    results
  end
end

Facter.add(:vault_certs) do
  confine osfamily: 'Debian'

  setcode do
    results = {}
    cert_dir = '/etc/ssl/vault-secrets'

    Dir["#{cert_dir}/*.json"].each { |filename|
      result = {}
      cert_name = File.basename(filename, ".json")
      cert_file = File.join(cert_dir, "#{cert_name}.pem")
      key_file = File.join(cert_dir, "#{cert_name}.key")
      if File.file?(cert_file) && File.file?(key_file)
        cert_m = Facter::Core::Execution.execute("openssl x509 -in #{cert_file} -noout -modulus", on_fail: nil)
        key_m = Facter::Core::Execution.execute("openssl rsa -in #{key_file} -noout -modulus", on_fail: nil)
        unless cert_m.nil? || key_m.nil?
          cert_modulus = cert_m.strip.split('=')[-1]
          key_modulus = key_m.strip.split('=')[-1]
          result['valid'] = cert_modulus == key_modulus
        end
        cert_dates = Facter::Core::Execution.execute("openssl x509 -in #{cert_file} -noout -dates", on_fail: nil)
        unless cert_dates.nil?
          begin
            expiration = Date.parse(cert_dates.split(%r{\n})[-1].split('=')[-1].strip)
            days_remaining = Integer(expiration - Date.today)
          rescue
            expiration = 'unknown'
            days_remaining = 'unknown'
          end
          result['expiration'] = expiration
          result['days_remaining'] = days_remaining
        end
      else
        result['valid'] = false
      end
      results[cert_name] = result
    }
    results
  end
end
