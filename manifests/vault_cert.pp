# @summary Issue and renew PKI certificate from Hashicorp Vault for arbitrary hostnames
#
# @param vault_uri The complete URL of the the Hashicorp Vault certificate issuing role API endpoint
#
# @param auth_path The Vault path of the authentication provider used by Puppet certificates
#
# @param cert_data A hash of values to be submitted with the certificate request.  The hash contents should
#   adhere to the keys/values supported/permitted by the PKI role and policy.
#
# @param days_before_renewal The number of days before expiration where the host certificate will be re-issued
#
# @example Issue a certificate from a Vault server with PKI secrets engine
#  vault_secrets:: vault_secrets { 'test':
#    vault_uri  => 'https://vault.example.com:8200/v1/pki/issue/example-com',
#    auth_path  => 'puppet-pki',
#    cert_data  => {
#      common_name => 'test.example.com',
#      alt_names   => 'localhost',
#      ip_sans     => '10.0.0.1,127.0.0.1',
#      ttl         => '168h',
#    }
#  }
#
define vault_secrets::vault_cert(
  String $vault_uri,
  String $auth_path,
  Hash $cert_data,
  Integer[1, 30] $days_before_renewal = 3,
  String $user = 'root',
  String $group = 'root',
) {

  include vault_secrets::vault_certs_extract

  $certs_dir = lookup('vault_secrets::certs_dir')
  $vault_cert = dig(fact('vault_certs'), $title)
  $cert_info = "${certs_dir}/${name}.json"
  $cert = "${certs_dir}/${name}.pem"
  $key = "${certs_dir}/${name}.key"
  $ca_chain = "${certs_dir}/${name}.chain.pem"
  $v = $vault_cert.dig('valid')
  $valid = $v ? {
    undef   => false,
    default => $v,
  }
  $x = $vault_cert.dig('days_remaining')
  $days_remaining = $x ? {
    undef   => 0,
    default => $x,
  }

  if !$valid or $days_remaining < $days_before_renewal {
    # Issue a new certificate from the Vault PKI endpoint and cache results in info file
    # Defer execution to the client side, so that client credentials are used to issue the
    # cert, and the puppetserver does not have access to the private key
    file {
      $cert_info:
        ensure  => present,
        content => Sensitive.new(Deferred('to_json', [Deferred('vault_cert', [$vault_uri, $auth_path, $cert_data])])),
        owner   => 'root',
        group   => 'root',
    }

    # Extract the certificate, chain and private key into the destination files
    exec {
      "vault-certs-extract-${name}-cert":
        command     => "/usr/local/bin/vault-certs-extract '${cert_info}' '${cert}' '${key}' '${ca_chain}'",
        refreshonly => true,
        subscribe   => File[$cert_info],
    }
  }

  # The extract helper will create these files
  # but ensure they have the correct ownership and permissions
  file {
    default:
      ensure => present,
      owner  => 'root',
      group  => 'root',
    ;
    $cert:
      mode    => '0644',
    ;
    $key:
      mode    => '0600',
    ;
    $ca_chain:
      mode    => '0644',
  }
}
