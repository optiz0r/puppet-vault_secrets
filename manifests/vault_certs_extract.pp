# @summary Deploys the vault-certs-extract helper
class vault_secrets::vault_certs_extract {

  $certs_dir = lookup('vault_secrets::certs_dir')

  file { $certs_dir:
    ensure => directory,
    owner  => 'root',
    group  => 'root',
    mode   => '0644',
  }

  file { '/usr/local/bin/vault-certs-extract':
    content => file('vault_secrets/vault-certs-extract'),
    owner   => 'root',
    group   => 'root',
    mode    => '0755',
  }

}
