=pod

=head1 NAME

Cisco::IMC

=head1 SYNOPSYS

	use Cisco::IMC;
	use Data::Dumper;

	my $cicm = Cisco::IMC->new( { host => $host, user => $user, password => $password } );

	my $dn = 'sys/rack-unit-1/locator-led';

	my $outConfig = $cicm->configResolveDn($dn) or die($@);
	# Alternatively:
	#my $outConfig = $cicm->getConfigDn($dn) or die($@);

	warn '$outConfig: ', Dumper($newOutConfig), ' ';

	# Perl L<XML::Simple> compatible hash representation of the inner XML snippet.
	my $inConfig = {
		equipmentLocatorLed	=> {
			adminState	=> 'on',
			dn		=> $dn,
		},
	};

	my $newOutConfig = $cicm->configConfMo($dn, $inConfig) or die($@);
	# Alternatively:
	#my $newOutConfig = $cicm->setConfig($dn, $inConfig) or die($@);

	warn '$newOutConfig: ', Dumper($newOutConfig), ' ';

	$cicm->logout();

=head1 DESCRIPTION

A simple Perl module for interacting with Cisco's Integrated Management
Controller (CIMC) on C-Series Rack-Mount Servers via their XML API.

Currently this is basically just a small wrapper around LWP::UserAgent
and XML::Simple for sending and parsing responses to and from the
controller and everything returned to the client is in the form of a
Perl data structure representing the XML.

If someone cared to they could extend this to spit back objects
representing the individual nodes in the hierarchy a bit more, but for
my purposes this seemed good enough for a first crack.  C<Data::Dumper>
is your friend :)

See Also: L<http://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/api/2-0/b_Cisco_IMC_api_2_0.html>

=head1 AUTHOR

Brian Kroth L<bpkroth@cs.wisc.edu>

=cut


# CANT: Make sure we're using the XS versions of XML::Simple and
# LWP::UserAgent if at all possible.

# http://www.perlmonks.org/?node_id=409517
$ENV{XML_SIMPLE_PREFERRED_PARSER} = 'XML::Parser';
# https://rt.cpan.org/Public/Bug/Display.html?id=78920
$ENV{PERL_NET_HTTPS_SSL_SOCKET_CLASS} = 'Net::SSL';


# Hacks to make sure that the order appeases some of the CIMC XML processing.
# See Also: http://stackoverflow.com/questions/1400850/how-can-i-order-tags-in-xmlsimples-output
package MyXMLSimple;	# my XML::Simple subclass 
use base 'XML::Simple';
use Data::Dumper;
use strict;
use warnings;

# Overriding the method here
sub sorted_keys
{
	my ($self, $name, $hashref) = @_;
	if ($name eq 'lsbootDef' || $name eq 'lsbootDevPrecision')	# only this tag I care about the order; (for now)
	{
		#warn('$name: ', $name, ' ') if ($::DEBUG > 2);
		#warn('Dumper($hashref): ', Dumper($hashref), ' ') if ($::DEBUG > 2);
		return sort {
			if (
				ref($hashref->{$a}) eq 'ARRAY' && ref($hashref->{$b}) eq 'ARRAY'
				&& defined($hashref->{$a}->[0]->{order}) && defined($hashref->{$b}->[0]->{order})
			) {
				return $hashref->{$a}->[0]->{order} <=> $hashref->{$b}->[0]->{order} 
			}
			else {
				return $a cmp $b;
			}
		} keys %{$hashref};
	}
	return $self->SUPER::sorted_keys($name, $hashref); # for the rest, I don't care!
}


package Cisco::IMC;

use strict;
use warnings;

use Carp;
use Data::Dumper;
use XML::Simple;

use LWP::UserAgent;
use HTTP::Request::Common;	# for POST constant

use Net::Ping;

use Sort::Versions;

use Exporter 'import';
our @EXPORT_OK = qw(
	&check_bool 
	&ascii_password_to_hex_encryption_key
	$DEFAULT_ADMIN 
	$DEFAULT_PASS
	$ALT_DEFAULT_PASS
);

our $DEFAULT_ADMIN	= 'admin';
our $DEFAULT_PASS	= 'password';
our $ALT_DEFAULT_PASS	= 'Cisco1234';

use constant TIMEOUT => 120;

# A set of supported top level XML request/response tags we're going to try and support.
my %SUPPORTED_XML = (
	aaaLogin		=> 1,
	aaaRefresh		=> 1,
	aaaLogout		=> 1,

	configResolveDn		=> 1,
	configResolveClass	=> 1,
	configResolveChildren	=> 1,
	configResolveParent	=> 1,

	configConfMo		=> 1,

	# Currently unsupported API methods:
	eventSubscribe		=> 0,
	eventUnsubscribe	=> 0,
	aaaGetComputeAuthTokens	=> 0,
	aaaKeepAlive		=> 0,

	# An undocumented error response.
	error			=> 1,
);


=pod

=head1 CONSTRUCTOR

=head2 
	my $cicm = Cisco::IMC->new( { host => $host, user => $user, password => $password } );

Constructs a new C<Cisco::IMC> object and gets an authentication cookie from the
given C<host> for the given C<user> and C<password> fields in the passed
options hashref.

The options hashref also accepts a C<debug> field 

=cut

sub new ($$) {
	my $class = shift;

	my ($opts) = @_;

	# Sanity check some required options.
	if (!$opts->{addr}) {
		croak('Missing or invalid addr option.');
	}
	if (!$opts->{host}) {
		$opts->{host} = $opts->{addr};	
	}
	if (!$opts->{user}) {
		croak('Missing or invalid user option.');
	}
	if (!$opts->{password}) {
		croak('Missing or invalid password option.');
	}
	if ($opts->{debug} && $opts->{debug} !~ /^[0-9]$/) {
		croak('Missing or invalid debug option.');
	}
	if ($opts->{readonly} && $opts->{readonly} !~ /^(0|1|yes|no|true|false)$/) {
		croak('Missing or invalid debug option.');
	}

	my $self = {
		addr			=> $opts->{addr},
		host			=> $opts->{host},
		user			=> $opts->{user},
		password		=> $opts->{password},
		debug			=> $opts->{debug},
		readonly		=> $opts->{readonly},
		# A reference to our LWP::UserAgent object:
		lwp_ua			=> undef,
		# A reference to our XML::Simple object:
		xs			=> undef,
		# Our current authentication cookie info:
		auth_cookie		=> undef,
		auth_cookie_valid_until	=> 0,
		
		# A cached value of the firmware version of the CIMC.
		firmware_version	=> undef,

		# A cached copy of the pidCatalog response for use in
		# determining what kind of hardware the machine has installed.
		pidCatalog		=> undef,	

		# A cached copy of the top level computeRackUnit response for
		# use in determining what kind of hardware the machine has
		# installed.
		computeRackUnit		=> undef,	
	};
	$self->{debug} = 0 unless ($self->{debug});
	$self->{readonly} = 0 unless ($self->{readonly});
	$self->{readonly} = check_bool($self->{readonly});

	$self->{host_addr} = Cisco::IMC::get_host_addr_string($self->{host}, $self->{addr});

	bless($self, $class);

	return $self;
}


# Make sure that we clean up after ourselves when the object is destroyed, else
# we can leave auth sessions lingering about which may causes us to get locked
# out if we hit the max of those.
sub DESTROY {
	my $self = shift;
	$self->logout();
}


=pod

=head1 PUBLIC METHODS

=cut

=pod

=head2 login(;$)

	my $authn_session_cookie = $cicm->login();

Attempts to start an authentication session with the CICM and returns the
cookie if successful.

Optionally accepts a boolean force flag to start a new session and cleanup any
existing ones.

This is not strictly necessary to call as other requests will attempt to
maintain a session cookie for you, but it can be useful in error testing.

=cut

sub login($;$) {
	my $self = shift;
	my ($force) = @_;

	return $self->_get_auth_cookie($force);
}


=pod

=head2 logout()

	$cicm->logout();

Clears any existing authentication sessions with the CICM rather than just
letting them timeout and cleans up the L<LWP::UserAgent>.

=cut

sub logout($) {
	my $self = shift;

	$self->_clear_auth_cookie();
	$self->{lwp_ua} = undef;
	$self->{xs} = undef;

	return 1;
}


=pod

=head2 ping()

	$cimc->ping();

Tries to see if the CIMC is still alive, by pinging it.  Returns a boolean.

=cut

sub ping($) {
	my $self = shift;

	my $ret;
	my $p = Net::Ping->new('tcp');
	# Try connecting to the www port instead of the echo port.
	$p->port_number(scalar(getservbyname('https', 'tcp')));
	$ret = $p->ping($self->{addr});
	$p->close();
	return $ret;
}


# The basic structure of a configResolve* query and response is so common, that
# we just wrap them all up in one sub, switch statements for the parameters.
sub _configResolve($$$;$$) {
	my $self = shift;
	my ($type, $value, $inHierarchical, $classId) = @_;

	my $inKey;
	my $outKey;
	if ($type eq 'configResolveDn' || $type eq 'configResolveParent') {
		$inKey = 'dn';
		$outKey = 'outConfig';
	}
	elsif ($type eq 'configResolveChildren') {
		$inKey = 'inDn';
		$outKey = 'outConfigs';
	}
	elsif ($type eq 'configResolveClass') {
		$inKey = 'classId';
		$outKey = 'outConfigs';
	}

	my $request = {
		$type	=> [
			{
				$inKey	=> $value,
			},
		],
	};
	if (defined($inHierarchical)) {
		$request->{$type}->[0]->{inHierarchical} = (check_bool($inHierarchical)) ? 'true' : 'false';
	}
	if (defined($classId)) {
		if ($type eq 'configResolveChildren') {
			$request->{$type}->[0]->{classId} = $classId;
		}
		else {
			croak("ERROR: classId parameter only accepted for configResolveChildren requests.")
		}
	}

	my $response = $self->_issue_request($request);
	my $outConfig = $response->{$type}->[0]->{$outKey}->[0];
	return $outConfig;

}


#	TODO: Add some comments on how to interact with the result.
=pod

=head2 configResolveDn($;$)

	my $dn = 'sys/rack-unit-1/locator-led';
	my $outConfig = $cicm->configResolveDn($dn) or die($@);


Returns an L<XML::Simple> hashref representation of an C<outConfig> XML response.

Optionally accepts a boolean value for the C<inHierarchical> attribute to
retrieve all child object data as well.

=cut

sub configResolveDn($$;$) {
	my $self = shift;
	return $self->_configResolve('configResolveDn', @_);
}


=pod

=head2 getConfigDn($;$)

An alias for C<configResolveDn()>.

=cut

sub getConfigDn($$;$) {
	my $self = shift;
	return $self->configResolveDn(@_);
}


=pod

=head2 configResolveClass($;$)

	my $classId = 'computeRackUnit';
	my $outConfig = $cicm->configResolveClass($classId) or die($@);

Returns an L<XML::Simple> hashref representation of an C<outConfig> XML response.

Optionally accepts a boolean value for the C<inHierarchical> attribute to
retrieve all child object data as well.

=cut

sub configResolveClass($$;$) { 
	my $self = shift;
	return $self->_configResolve('configResolveClass', @_);
}


=pod

=head2 getConfigClass($;$)

An alias for C<configResolveClass()>.

=cut

sub getConfigClass($$;$) {
	my $self = shift;
	return $self->configResolveClass(@_);
}


=pod

=head2 configResolveChildren($;$$)

	my $dn = 'sys/rack-unit-1/boot-policy';
	my $outConfig = $cicm->configResolveChildren($dn) or die($@);

Returns an L<XML::Simple> hashref representation of an C<outConfig> XML response.

Optionally accepts a boolean value for the C<inHierarchical> attribute to
retrieve all child object data as well.

Second optional argument can be used to restrict retrieved children to those
of class C<classId>.

=cut

sub configResolveChildren($$;$$) { 
	my $self = shift;
	return $self->_configResolve('configResolveChildren', @_);
}


=pod

=head2 getConfigChildren($;$)

An alias for C<configResolveChildren()>.

=cut

sub getConfigChildren($$;$) {
	my $self = shift;
	return $self->configResolveChildren(@_);
}


=pod

=head2 configResolveParent($;$)

	my $dn = 'sys/rack-unit-1/boot-policy/efi-read-only';
	my $outConfig = $cicm->configResolveParent($dn) or die($@);

Returns an L<XML::Simple> hashref representation of an C<outConfig> XML response.

Optionally accepts a boolean value for the C<inHierarchical> attribute to
retrieve all child object data as well.

=cut

sub configResolveParent($$;$) { 
	my $self = shift;
	return $self->_configResolve('configResolveParent', @_);
}


=pod

=head2 getConfigParent($;$)

An alias for C<configResolveParent()>.

=cut

sub getConfigParent($$;$) {
	my $self = shift;
	return $self->configResolveParent(@_);
}


=pod

=head2 configResolveParent($$;$)

	my $dn = 'sys/rack-unit-1/locator-led';
	my $inConfig = {
		equipmentLocatorLed	=> [
			{
				dn		=> $dn,
				adminState	=> 'on',
			},
		],
	};
	my $outConfig = $cicm->configConfMo($inConfig, $dn) or die($@);

Returns an L<XML::Simple> hashref representation of an C<outConfig> XML response.

Optionally accepts a boolean value for the C<inHierarchical> attribute.

=cut


#sub configConfMo($$$;$) {
sub configConfMo($$$) {
	my $self = shift;
	my ($inConfig, $dn, $inHierarchical) = @_;

	if (ref($inConfig) ne 'HASH') {
		croak('ERROR: Invalid $inConfig argument: ', Dumper($inConfig).' ');
	}

	my $request = {
		configConfMo	=> [
			{
				dn		=> $dn,
				inConfig	=> [ $inConfig ],
			},
		],
	};
	# Lies:
	# See Also: RACK-IN.xsd
	## At least one config request type claims to allow resetting to
	## defaults by passing a request with a missing inConfig element.
	## See Also: http://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/api/2-0/b_Cisco_IMC_api_2_0/b_Cisco_IMC_api_2_0_appendix_0110.html#reference_9DBE7486B7EE4F399398645FEC9333D9__section_1E70DB14FE9E451BB10782B66B0EDBC5
	#if (scalar(keys(%$inConfig))) {
	#	$request->{configConfMo}->[0]->{inConfig} = [ $inConfig ];
	#}

	if (defined($inHierarchical)) {
		$request->{configConfMo}->[0]->{inHierarchical} = (check_bool($inHierarchical)) ? 'true' : 'false';
	}

	if (check_bool($self->{readonly})) {
		carp("WARNING: Refusing to issue request in readonly mode.  You may get unexpected results: ".Dumper($request).' ');
		return $inConfig;
	}

	my $response = $self->_issue_request($request);
	my $outConfig = $response->{configConfMo}->[0]->{outConfig}->[0];
	return $outConfig;
}


=pod

=head2 setConfig($$;$)

An alias for C<configConfMo()>.

=cut

#sub setConfig($$$;$) {
sub setConfig($$$) {
	my $self = shift;
	return $self->configConfMo(@_);
}


=pod

=head2 get_rack_unit_info()

	warn Dumper($cimc->get_rack_unit_info()), ' ';

Gets (and caches) the computeRackUnit info.

=cut

sub get_rack_unit_info($;$) {
	my $self = shift;
	my ($force) = @_;

	if ($force || !defined($self->{computeRackUnit}) || !scalar(keys(%{$self->{computeRackUnit}}))) {
		carp("Getting rack-unit info on $self->{host_addr}.") if ($self->{debug});
		my $dn = 'sys/rack-unit-1';
		# NOTE: We're just getting the top level here.
		my $response = $self->getConfigDn($dn) or die($@);
		$self->{computeRackUnit} = $response;
	}

	return $self->{computeRackUnit};
}


=pod

=head2 get_machine_faults()

	my (@faults) = $cimc->get_machine_faults();

Ask the CIMC what faults it thinks the machine currently has.

NOTE: This unfortunately can't provide information about failed disks in
machines with passthru HBAs - there's no smarts there to check the SMART status
:P

=cut

sub get_machine_faults($) {
	my $self = shift;

	carp("Getting machine faults on $self->{host_addr}.") if ($self->{debug});

	my $response = $self->getConfigClass('faultInst');
	return () unless ($response && $response->{faultInst});

	return @{$response->{faultInst}};
}


=pod

=head2 get_product_inventory()

	warn Dumper($cimc->get_product_inventory()), ' ';

Gets (and caches) the pidCatalog info.

=cut

sub get_product_inventory($;$) {
	my $self = shift;
	my ($force) = @_;

	if ($force || !defined($self->{pidCatalog}) || !scalar(keys(%{$self->{pidCatalog}}))) {
		carp("Getting machine product inventory on $self->{host_addr}.") if ($self->{debug});
		my $dn = 'sys/rack-unit-1/board/pid';
		my $response = $self->getConfigDn($dn, 1) or die($@);
		$self->{pidCatalog} = $response;
	}

	return $self->{pidCatalog};
}

=pod

=head2 load_product_inventory()

	# Powers the machine on and waits until the pidCatalog is available.
	$cimc->load_product_inventory();

A type agnostic version of C<CloudLab::Cisco::IMCs::load_machine_inventory()>.

=cut

sub load_product_inventory($) {
	my $self = shift;

	$self->set_power_mode('up');

	$self->wait_response(180, sub {
		carp("Waiting for pidCatalog to load ...") if ($self->{debug});
		my $response = $self->get_product_inventory(1);
		if (scalar(grep { $_ =~ /^pidCatalog/ } keys(%{$response->{pidCatalog}->[0]}))) {
			return 1;
		}
		else {
			return 0;
		}
	});

	return $self->{pidCatalog};
}

=pod

=head2 has_vNic_adaptor()

	$cimc->reset_vNic_adaptors() if ($cimc->has_vNic_adaptor());

Checks to see if the machine looks to have a VIC Network Adaptor that we known
how to manage.
Else, it might have one of the Intel 10G NICs (eg: X520).

=cut

sub has_vNic_adaptor($) {
	my $self = shift;
	my $response = $self->get_product_inventory();
	return grep { 
		$_->{device} eq '0x0042'		# VIC Management Controller, pid: UCSC-MLOM-CSC-02
		&& $_->{vendor} eq '0x1137' 		# Cisco
		&& $_->{pid} eq 'UCSC-MLOM-CSC-02'
		} @{$response->{pidCatalog}->[0]->{pidCatalogPCIAdapter}};
}

=pod

=head2 has_x520_nic()

Checks to see if the machine looks to have an Intel X520 NIC.

=cut

sub has_x520_nic() {
	my $self = shift;
	my $response = $self->get_product_inventory();
	return grep { 
		$_->{device} eq '0x10fb'	# 82599ES 10-Gigabit SFI/SFP+ Network Connection
		&& $_->{vendor} eq '0x8086' 	# Intel
		&& $_->{pid} eq 'N2XX-AIPCI01'
		} @{$response->{pidCatalog}->[0]->{pidCatalogPCIAdapter}};
}

=pod

=head2 has_raid_hba()
	
	$cimc->reset_raid_hba_adaptors if ($cimc->has_raid_hba());

Checks to see if the machine looks to have a RAID HBA that we know how to manage.
Else, it might be a passthru controller that has no special smarts built in to it.

=cut

sub has_raid_hba($) {
	my $self = shift;
	my $response = $self->get_product_inventory();
	return grep { 
		$_->{device} eq '0x005d'	# MegaRAID SAS-3 3108 [Invader]
		&& $_->{vendor} eq '0x1000' 	# LSI
		&& $_->{pid} eq 'UCSC-MRAID12G'
		} @{$response->{pidCatalog}->[0]->{pidCatalogPCIAdapter}};
}

=pod

=head2 has_passthru_hba()

Checks to see if the machine looks to have a passthru HBA controller.

=cut

sub has_passthru_hba() {
	my $self = shift;
	my $response = $self->get_product_inventory();
	return grep { 
		$_->{device} eq '0x0090'	# SAS3108 PCI-Express Fusion-MPT SAS-3
		&& $_->{vendor} eq '0x1000' 	# LSI
		&& $_->{pid} eq 'UCSC-SAS12GHBA'
		} @{$response->{pidCatalog}->[0]->{pidCatalogPCIAdapter}};
}

=pod

=head2 get_model()

=cut

sub get_model($) {
	my $self = shift;

	carp("Getting model info for $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_rack_unit_info();
	return $response->{computeRackUnit}->[0]->{model};
}

=pod

=head2 get_memory_info()

	my ($totalMemory, $memorySpeed) = $cimc->get_memory_info();

Returns various basic info about the memory installed on the machine.

=cut

sub get_memory_info($) {
	my $self = shift;

	carp("Getting memory info for $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_rack_unit_info();
	return (
		$response->{computeRackUnit}->[0]->{totalMemory},
		$response->{computeRackUnit}->[0]->{memorySpeed}
	);
}

=pod

=head2 get_cpu_info()

	my ($totalCPUs, $totaCores, $totalThreads, $cpuSpeed, $cpuModel) = $cimc->get_cpu_info();

Returns various basic info about the CPU(s) installed on the machine.

=cut

sub get_cpu_info($) {
	my $self = shift;

	carp("Getting CPU info for $self->{host_addr}.") if ($self->{debug});

	my $ru_resp = $self->get_rack_unit_info();
	my $pid_resp = $self->get_product_inventory();

	# TODO: This currently assumes that all sockets have the same speed/model.
	# We should check/verify that and alert if its not the case.

	return (
		$ru_resp->{computeRackUnit}->[0]->{numOfCpus},
		$ru_resp->{computeRackUnit}->[0]->{numOfCores},
		$ru_resp->{computeRackUnit}->[0]->{numOfThreads},
		$pid_resp->{pidCatalog}->[0]->{pidCatalogCpu}->[0]->{currentspeed},
		$pid_resp->{pidCatalog}->[0]->{pidCatalogCpu}->[0]->{model}
	);
}

=pod

=head2 get_vNic_adaptors()

	warn Dumper($cimc->get_vNic_adaptors()), ' ';

Gets the vNic adaptors for the CIMC.

=cut

sub get_vNic_adaptors($) {
	my $self = shift;

	carp("Getting vNic adaptors on $self->{host_addr}.") if ($self->{debug});

	my $class = 'adaptorUnit';

	my $response = $self->getConfigClass($class) or die($@);
	return $response->{$class};
}


=pod

=head2 reset_vNic_adaptor($vna_dn)

	$cimc->reset_vNic_adaptor($vna_dn)) or die($@);

Reset the vNic adaptor settings at the given C<$dn> for the CIMC.

=cut

sub reset_vNic_adaptor($$) {
	my $self = shift;
	my ($vna_dn) = @_;

	carp("Resetting vNic $vna_dn on $self->{host_addr}.") if ($self->{debug});

	# NOTE: This was copied/edited from the set_raid_hba_adaptor_jbod_mode() sub.
	carp("Making sure that $self->{host_addr} is powered on so we can communicate with the VIC.") if ($self->{debug});
	if ($self->set_power_mode('up')) {
		$self->wait_response(180, sub {
			carp("Waiting for VIC option ROM to POST ...") if ($self->{debug});

			# Assuming that's the case as soon as the network
			# controller can report on the power status of a drive.
			# HACK: But that's not actually true since it caches
			# that data, so just wait instead.
			# This only happens if we actually had to power on the
			# machine anyways.

			$self->{cimc}->getConfigDn('sys');
			# We're just waiting now, so we don't care what the
			# response was, just want to keep the connection alive.
			return 0;

=hack_disabled
			my $dn = $vna_dn;
			my $response = $self->getConfigDn($dn);
			if (
				$response
				&& $response->{serial}
			) {
				return 1;
			}
			else {
				return 0;
			}
=cut
		}) unless ($self->{readonly});
	}

	my $inConfig = {
		adaptorUnit	=> [
			{
				adminState	=> 'adaptor-reset-default',
				dn		=> $vna_dn,
			},
		],
	};

	my $response = $self->setConfig($inConfig, $vna_dn) or die($@);
	return $response;
}


=pod

=head2 reset_vNic_adaptors()

	$cimc->reset_vNic_adaptors() or die($@);

Resets the vNic adaptors on the CIMC.

=cut

sub reset_vNic_adaptors($) {
	my $self = shift;

	carp("Resetting vNic adaptors from $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_vNic_adaptors();

	foreach my $vna_resp (@$response) {
		$self->reset_vNic_adaptor($vna_resp->{dn}) or die($@);
	}

	return 1;
}


=pod

=head2 get_vNic_settings(;$$$)

	warn Dumper($cimc->get_vNic_settings($inHierachical, $type, $adaptor_dn)), ' ';

Gets the vNic settings for the CIMC, optionally restricted to a particular
C<$type> and/or parent C<$adaptor_dn>.

=cut

sub get_vNic_settings($;$$$) {
	my $self = shift;
	my ($inHierarchical, $type, $adaptor_dn) = @_;

	$inHierarchical = 1 unless (defined($inHierarchical));
	$type = 'all' unless ($type);

	carp("Getting $type vNic settings on $self->{host_addr}.") if ($self->{debug});

	my $class;
	if ($type eq 'all') {
		$class = 'adaptorUnit';
	}
	elsif ($type eq 'ext') {
		$class = 'adaptorExtEthIf';
	}
	elsif ($type eq 'host') {
		$class = 'adaptorHostEthIf';
	}
	elsif ($type eq 'fc') {
		$class = 'adaptorHostFcIf';
	}
	else {
		croak("ERROR: Unexpected type: '$type'.");
	}

	my $response;
	if ($adaptor_dn) {
		$response = $self->getConfigChildren($adaptor_dn, $inHierarchical, $class) or die($@);
	}
	else {
		$response = $self->getConfigClass($class, $inHierarchical) or die($@);
	}
	return $response->{$class};
}


=pod

=head2 get_Nic_adaptors()

	warn Dumper($cimc->get_Nic_adaptors()), ' ';

Gets the non-vNic Nic adaptors for the CIMC.

=cut

sub get_Nic_adaptors($) {
	my $self = shift;

	carp("Getting standard network adapters on $self->{host_addr}.") if ($self->{debug});

	my $class = 'networkAdapterUnit';

	my $response = $self->getConfigClass($class) or die($@);
	return $response->{$class};
}


=pod

=head2 get_Nic_settings(;$$$)

	warn Dumper($cimc->get_Nic_settings($inHierachical, $networkadapter_dn)), ' ';

Gets the non-vNic Nic settings for the CIMC, optionally restricted to a
particular parent C<$networkadapter_dn>.

=cut

sub get_Nic_settings($;$$$) {
	my $self = shift;
	my ($inHierarchical, $networkadapter_dn) = @_;

	carp("Getting network adapter settings on $self->{host_addr}.") if ($self->{debug});

	$inHierarchical = 1 unless (defined($inHierarchical));

	my $class = 'networkAdapterUnit';

	my $response;
	if ($networkadapter_dn) {
		$response = $self->getConfigDn($networkadapter_dn, $inHierarchical) or die($@);
	}
	else {
		$response = $self->getConfigClass($class, $inHierarchical) or die($@);
	}
	return $response->{$class};
}


=pod

=head2 get_mgmtIf_settings(;$$$)

	warn Dumper($cimc->get_mgmtIf_settings()), ' ';

Gets the CIMC mgmtIf settings.

=cut

sub get_mgmtIf_settings($;$$$) {
	my $self = shift;

	carp("Getting CIMC mgmtIf settings on $self->{host_addr}.") if ($self->{debug});

	my $class = 'mgmtIf';

	my $response = $self->getConfigClass($class, 1) or die($@);

	return $response->{$class};
}


=pod

=head2 get_vMedia_maps()

	warn Dumper($cimc->get_vMedia_maps()), ' ';

Gets the currently attached vMedia for the CIMC.

=cut

sub get_vMedia_maps($) {
	my $self = shift;

	carp("Getting vMedia maps on $self->{host_addr}.") if ($self->{debug});

	my $class = 'commVMediaMap';

	my $response = $self->getConfigClass($class) or die($@);
	return $response->{$class};
}


=pod

=head2 remove_vMedia_map($dn)

	$cimc->remove_vMedia_dn($vmedia_resp->{dn}) or die($@);

Removes the vMedia map at the given C<$dn> for the CIMC.

=cut

sub remove_vMedia_map($$) {
	my $self = shift;
	my ($vmedia_dn) = @_;

	carp("Removing vMedia map $vmedia_dn from $self->{host_addr}.") if ($self->{debug});

	my $inConfig = {
		commVMedia	=> [
			{
				dn	=> $vmedia_dn,
				status	=> 'deleted',
			},
		],
	};

	my $response = $self->setConfig($inConfig, $vmedia_dn, 1) or die($@);
	return $response;
}


=pod

=head2 remove_vMedia_maps()

	$cimc->remove_vMedia_maps() or die($@);

Removes the vMedia maps from the CIMC.

=cut

sub remove_vMedia_maps($) {
	my $self = shift;

	carp("Removing vMedia maps from $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_vMedia_maps();

	foreach my $vmedia_resp (@$response) {
		$self->remove_vMedia_map($vmedia_resp->{dn}) or die($@);
	}

	return 1;
}


# TODO: Rename this to not include passthrough controllers since they don't show up under these classes.

=pod

=head2 get_raid_hba_adaptors(;$)

	warn Dumper($cimc->get_raid_hba_adaptors()), ' ';

Gets the HBA/RAID storage controller adaptors for the CIMC.

Takes an optional C<$inHierarchical> option.

=cut

sub get_raid_hba_adaptors($;$) {
	my $self = shift;
	my ($inHierarchical) = @_;

	carp("Getting RAID HBA adaptors on $self->{host_addr}.") if ($self->{debug});

	my $class = 'storageController';

	my $response = $self->getConfigClass($class, $inHierarchical) or die($@);
	return $response->{$class};
}


=pod 

=head2 reset_raid_hba_adaptor($)

	$cimc->reset_raid_hba_adaptor($hba_dn) or die($@);

Resets the HBA adaptor given at C<$hba_dn> for the CIMC.

=cut

sub reset_raid_hba_adaptor($$) {
	my $self = shift;
	my ($hba_dn) = @_;

	my $inConfig;

	carp("Clearing foreign config from RAID HBA adaptor at $hba_dn for $self->{host_addr}.") if ($self->{debug});

	$inConfig = {
		storageController	=> [
			{
				adminAction	=> 'clear-foreign-config',
				dn		=> $hba_dn,
			},
		],
	};
	$self->setConfig($inConfig, $hba_dn) or carp($@);

	carp("Resetting RAID HBA adaptor at $hba_dn for $self->{host_addr}.") if ($self->{debug});

	# FIXED: (see remove_virtual_drives below) 
	# This doesn't appear to actually delete all of the virtual devices.
	# We may have to enumerate them and delete them one at a time instead.
	$inConfig = {
		storageController	=> [
			{
				adminAction	=> 'delete-all-vds-reset-pds',
				dn		=> $hba_dn,
			},
		],
	};
	$self->setConfig($inConfig, $hba_dn) or die($@);

	# DONE: Hmm, which one of these?  Or both?  Nah, just the first one.
	# UPDATE: Nevermind, need both, but reverse the order.

	# Might need a server reset too though.

	return 1;
}


=pod

=head2 reset_raid_hba_adaptors();

	$cimc->reset_raid_hba_adaptors() or die($@);

Resets all of the HBA adaptors for the CIMC.

=cut

sub reset_raid_hba_adaptors($) {
	my $self = shift;

	carp("Resetting RAID HBA adaptors for $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_raid_hba_adaptors();

	foreach my $ha_resp (@$response) {
		$self->reset_raid_hba_adaptor($ha_resp->{dn}) or die($@);
	}

	return 1;
}


=pod

=head2 set_raid_hba_adaptor_jbod_mode($)

	$cimc->set_raid_hba_adaptor_jbod_mode($hba_dn, $jbod_mode) or die($@);

Sets the JBOD mode for the HBA given by C<$hba_dn> on the CIMC.

NOTE: You probably need to make run something like C<load_inventory()> first.

=cut

sub set_raid_hba_adaptor_jbod_mode($$$) {
	my $self = shift;
	my ($hba_dn, $jbod_mode) = @_;

	$jbod_mode = (check_bool($jbod_mode)) ? 'true' : 'false';

	carp("Checking RAID HBA $hba_dn JBOD mode for $self->{host_addr}.") if ($self->{debug});
	
	# DONE: Make this $model dependent.  Or independent.
	my $response = $self->getConfigDn("$hba_dn/controller-settings") or die($@);
	if ($response->{storageControllerSettings}->[0]->{enableJbod} eq $jbod_mode) {
		return 1;
	}
	# else, need to make the change

	carp("Setting RAID HBA $hba_dn JBOD mode to $jbod_mode for $self->{host_addr}.") if ($self->{debug});

	carp("Making sure that $self->{host_addr} is powered on so we can communicate with the RAID HBA.") if ($self->{debug});
	if ($self->set_power_mode('up')) {
		$self->wait_response(180, sub {
			carp("Waiting for RAID/HBA option ROM to POST ...") if ($self->{debug});

			# Assuming that's the case as soon as the storage
			# controller can report on the power status of a drive.
			# HACK: But that's not actually true since it caches
			# that data, so just wait instead.
			# This only happens if we actually had to power on the
			# machine anyways.

			$self->{cimc}->getConfigDn('sys');
			# We're just waiting now, so we don't care what the
			# response was, just want to keep the connection alive.
			return 0;

=hack_disabled
			my $dn = "$hba_dn/pd-1/general-props";
			my $response = $self->getConfigDn($dn);
			if (
				$response 
				&& $response->{storageLocalDiskProps}->[0]->{health} 
				&& $response->{storageLocalDiskProps}->[0]->{powerState} eq 'active'
			) {
				return 1;
			}
			else {
				return 0;
			}
=cut
		}) unless ($self->{readonly});
	}

	my $inConfig = {
		storageController	=> [
			{
				adminAction	=> (check_bool($jbod_mode)) ? 'enable-jbod' : 'disable-jbod',
				dn		=> $hba_dn,
			},
		],
	};
	$self->setConfig($inConfig, $hba_dn) or die($@);

	sleep(5);
	$self->wait_response(90, sub {
		carp("Waiting for RAID HBA option to reconfigure JBOD mode ...") if ($self->{debug});

		my $dn = "$hba_dn/controller-settings";
		my $response = $self->getConfigDn($dn);
		if ($response && $response->{storageControllerSettings}->[0]->{enableJbod} eq $jbod_mode) {
			return 1;
		}
		else {
			return 0;
		}
	});

	return 1;
}


=pod

=head2 set_raid_hba_adaptors_jbod_mode();

	$cimc->set_raid_hba_adaptors_jbod_mode() or die($@);

Sets all of the HBA adaptor's JBOD modes on the CIMC.

=cut

sub set_raid_hba_adaptors_jbod_mode($$) {
	my $self = shift;
	my ($jbod_mode) = @_;

	carp("Setting RAID HBA adaptors JBOD mode to $jbod_mode for $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_raid_hba_adaptors();

	foreach my $ha_resp (@$response) {
		$self->set_raid_hba_adaptor_jbod_mode($ha_resp->{dn}, $jbod_mode) or die($@);
	}

	return 1;
}


=pod

=head2 get_raid_hba_virtual_drives()

	warn Dumper($cimc->get_raid_hba_virtual_drives()), ' ';

Gets the hba virtual drives for the CIMC.

=cut

sub get_raid_hba_virtual_drives($;$$) {
	my $self = shift;
	my ($inHierarchical, $hba_dn) = @_;

	carp("Getting RAID HBA virtual drives on $self->{host_addr}.") if ($self->{debug});

	my $class = 'storageVirtualDrive';

	my $response;
	if ($hba_dn) {
		$response = $self->getConfigChildren($hba_dn, $inHierarchical, $class) or die($@);
	}
	else {
		$response = $self->getConfigClass($class, $inHierarchical) or die($@);
	}
	return $response->{$class};
}


=pod

=head2 remove_raid_hba_virtual_drive($dn)

	$cimc->remove_raid_hba_virtual_drive($vd_resp->{dn}) or die($@);

Removes the hba virtual drive at the given C<$dn> for the CIMC.

=cut

sub remove_raid_hba_virtual_drive($$) {
	my $self = shift;
	my ($vd_dn) = @_;

	carp("Removing virtual drive $vd_dn from RAID HBA on $self->{host_addr}.") if ($self->{debug});

	my $inConfig = {
		storageVirtualDrive	=> [
			{
				dn	=> $vd_dn,
				status	=> 'deleted',
			},
		],
	};

	my $response = $self->setConfig($inConfig, $vd_dn, 1) or die($@);
	return $response;
}


=pod

=head2 remove_raid_hba_virtual_drives()

	$cimc->remove_raid_hba_virtual_drives() or die($@);

Removes the hba virtual drives from the CIMC.

=cut

sub remove_raid_hba_virtual_drives($) {
	my $self = shift;

	carp("Removing virtual drives from HBA on $self->{host_addr}.") if ($self->{debug});

	my $response = $self->get_raid_hba_virtual_drives();

	foreach my $vd_resp (@$response) {
		$self->remove_raid_hba_virtual_drive($vd_resp->{dn}) or die($@);
	}

	return 1;
}


=pod

=head2 get_raid_hba_physical_drives()

	warn Dumper($cimc->get_raid_hba_physical_drives()), ' ';

Gets the HBA physical drives for the CIMC.

=cut

sub get_raid_hba_physical_drives($;$$) {
	my $self = shift;
	my ($inHierarchical, $hba_dn) = @_;

	carp("Getting RAID HBA physical drives on $self->{host_addr}.") if ($self->{debug});

	my $class = 'storageLocalDisk';

	my $response;
	if (defined($hba_dn)) {
		$response = $self->getConfigChildren($hba_dn, $inHierarchical, $class) or die($@);
	}
	else {
		$response = $self->getConfigClass($class, $inHierarchical) or die($@);
	}
	return $response->{$class};
}


=pod

=head2 set_raid_hba_physical_drive_jbod_mode($dn)

	$cimc->set_raid_hba_physical_drive_jbod_mode($pd_resp->{dn}) or die($@);

Sets the physical drive given by C<$dn> on the HBA to JBOD mode for the CIMC.

=cut

sub set_raid_hba_physical_drive_jbod_mode($$) {
	my $self = shift;
	my ($pd_dn) = @_;

	carp("Setting HBA physical drive $pd_dn on $self->{host_addr} to JBOD mode.") if ($self->{debug});

	my $inConfig = {
		storageLocalDisk	=> [
			{
				dn		=> $pd_dn,
				adminAction	=> 'make-jbod',
			},
		],
	};

	my $response = $self->setConfig($inConfig, $pd_dn, 1) or die($@);
	return $response;
}


=pod

=head2 set_raid_hba_physical_drives_jbod_mode()

	$cimc->set_raid_hba_physical_drives_jbod_mode() or die($@);

Sets the physical drives on the HBA to JBOD mode for the CIMC.

=cut

sub set_raid_hba_physical_drives_jbod_mode($) {
	my $self = shift;

	carp("Setting HBA physical drives on $self->{host_addr} to JBOD mode.") if ($self->{debug});

	my $response = $self->get_raid_hba_physical_drives();

	foreach my $pd_resp (@$response) {
		if ($pd_resp->{pdStatus} ne 'JBOD') {
			$self->set_raid_hba_physical_drive_jbod_mode($pd_resp->{dn}) or die($@);
		}
	}

	return 1;
}


=pod

=head2 get_hostname()

	$cimc->get_hostname();

Returns the hostname for the CIMC.

=cut

sub get_hostname($) {
	my $self = shift;

	carp("Getting CIMC hostname on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/rack-unit-1/mgmt/if-1';

	my $response = $self->getConfigDn($dn) or die($@);
	return $response->{mgmtIf}->[0]->{hostname};
}


=pod

=head2 set_hostname($hostname)

	$cimc->set_hostname('pc-c220m4-r06-01-mng');

Sets the hostname for the CIMC.

=cut

sub set_hostname($$) {
	my $self = shift;
	my ($hostname) = @_;

	carp("Checking hostname on $self->{host_addr}.") if ($self->{debug});

	# NOTE: This will cause the network to reset, so make sure to check and
	# see if it actually needs to change first.

	my $dn = 'sys/rack-unit-1/mgmt/if-1';

	my $response = $self->getConfigDn($dn) or die($@);

	if ($response->{mgmtIf}->[0]->{hostname} ne $hostname) {
		carp("Setting hostname to $hostname on $self->{host_addr}.") if ($self->{debug});

		my $inConfig = {
			mgmtIf	=> [
				{
					dn		=> $dn,
					hostname	=> $hostname,
				},
			],
		};
		$self->setConfig($inConfig, $dn) or die($@);

		# Wait a moment for the host to return.
		$self->wait_response(20, sub {
			carp("Waiting for $self->{host_addr} to return ...") if ($self->{debug});
			$dn = 'sys';
			$response = $self->getConfigDn($dn);
			if ($response && $response->{topSystem}) {
				return 1;
			}
			else {
				return 0;
			}
		});
	}
	else {
		# Already done.
	}
	return 1;
}


=pod

=head2 get_timezone()

	warn Dumper($cimc->get_timezone()), ' ';

Returns the timezone for the CIMC.

=cut

sub get_timezone($) {
	my $self = shift;

	carp("Getting CIMC timezone on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys';

	my $response = $self->getConfigDn($dn) or die($@);
	return $response->{topSystem}->[0]->{timeZone};
}


=pod

=head2 set_timezone($)

	$cimc->set_timezone('America/Chicago') or die($@);

Sets the timezone on the CIMC.

=cut

#sub set_timezone($;$) {
sub set_timezone($$) {
	my $self = shift;
	my ($timezone) = @_;
	#$timezone = 'America/Chicago' unless ($timezone);

	carp("Setting timezone to $timezone on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys';
	my $inConfig = {
		topSystem	=> [
			{
				timeZone	=> $timezone, 
				dn		=> $dn,
			},
		],
	};
	$self->setConfig($inConfig, $dn) or die($@);

	return 1;
}


=pod

=head2 get_indicator_led()

	warn Dumper($cimc->get_indicator_led());

Returns the state of the indicator light for the CIMC.

=cut

sub get_indicator_led($) {
	my $self = shift;

	carp("Getting indicator LED status on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/rack-unit-1/locator-led';
	my $response = $self->getConfigDn($dn) or die($@);

	return $response->{equipmentLocatorLed}->[0]->{operState};
}


=pod

=head2 set_indicator_led($state)

	$cimc->set_indicator_led('on');

Changes the state of the indicator light for the CIMC.

=cut

sub set_indicator_led($$) {
	my $self = shift;
	my ($state) = @_;

	$state = (check_bool($state)) ? 'on' : 'off';

	carp("Turning indicator led $state for $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/rack-unit-1/locator-led';
	my $inConfig = {
		equipmentLocatorLed	=> [
			{
				dn		=> $dn,
				adminState	=> $state,
			},
		],
	};
	my $response = $self->setConfig($inConfig, $dn);

	carp("Failed to turn indicator led $state for $self->{host_addr}.  $@ ") unless ($response);
	
	return $response;
}


=pod

=head2 get_sel_debug_log_info()

	warn Dumper($cimc->get_sel_debug_log_info());

Returns the state of the sys/sel debug log.

=cut

sub get_sel_debug_log_info($) {
	my $self = shift;

	carp("Getting CIMC SEL log info on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/rack-unit-1/mgmt/log-SEL-0';
	my $response = $self->getConfigDn($dn, 1) or die($@);

	return $response->{sysdebugMEpLog}->[0];
}


=pod

=head2 clear_sel_debug_log()

	warn Dumper($cimc->clear_sel_debug_log());

Clears the SEL debug log.

=cut

sub clear_sel_debug_log($) {
	my $self = shift;

	carp("Clearing CIMC SEL log on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/rack-unit-1/mgmt/log-SEL-0';
	my $inConfig = {
		sysdebugMEpLog	=> [
			{
				dn		=> $dn,
				type		=> 'SEL',
				adminState	=> 'clear',
			},
		],
	};
	my $response = $self->setConfig($inConfig, $dn) or die($@);

	return $response;
}


=pod

=head2 get_power_mode()

	warn Dumper($cimc->get_power_mode());

Gets the current power state of the server.

=cut

sub get_power_mode($) {
	my $self = shift;

	carp("Getting node power mode on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/rack-unit-1';
	my $response = $self->getConfigDn($dn) or die($@);

	return $response->{computeRackUnit}->[0]->{operPower};
}


=pod

=head2 set_power_mode($)

	$cimc->set_power_mode('up') or die($@);

Changes the power state of the server.

=cut

sub set_power_mode($$) {
	my $self = shift;
	my ($mode) = @_;

	# Some NOTEs on the various operation modes we can try and do:
	#
	# bmc-reset-immediate: 
	# 	Reboot the CIMC.
	# bmc-reset-default: 
	# 	Resets the CIMC to defaults, thus requires another
	# 	couple of rounds of setup-cloudlab-cisco-cimc to get
	# 	the vlans/addresses right again.
	# cmos-reset-immediate: 
	# 	Reset the CMOS settings, thus probably requires another
	# 	setup-cloudlab-cisco-cimc.pl.
	#	NOTE: power must be off to do this.

	my $operPower = $self->get_power_mode();

	my $op;

	# For the first handful, we don't care what power state the machine is
	# in since they only affect the CIMC, not the node itself.
	if ($mode =~ /^(bmc-reset-immediate|bmc-reset-default)$/) {
		# Just do it:
		$op = $mode;
	}
	elsif ($mode =~ /^(up|down|soft-shut-down|cycle-immediate|hard-reset-immediate|diagnostic-interrupt|cmos-reset-immediate)$/) {
		if ($operPower eq 'off') { 
			if ($mode eq 'up' || $mode eq 'cmos-reset-immediate') {
				$op = $mode;
			}
			elsif ($mode =~ /^(cycle-immediate|hard-reset-immediate)$/) {
				# They really want to just power the machine on.
				$op = 'up';
			}
			# else, nothing else really makes sense, just skip it.
		}
		elsif ($operPower eq 'on') {
			if ($mode eq 'cmos-reset-immediate') {
				carp("Must be powered off to perform a cmos-reset-immediate operation.");
			}
			elsif ($mode ne 'up') {
				# pretty much everything else makes sense
				$op = $mode;
			}
			# else, just skip it
		}
		else {
			carp("Unhandled operPower state: '$operPower'.  Will attempt to set adminPower to '$mode' anyways, but it may fail.");
			$op = $mode;
		}
	}
	else {
		croak("Unhandled adminPower operation mode: '$mode'.");
	}

	if ($op) {
		carp("Setting node adminPower state to $op on $self->{host_addr}.") if ($self->{debug} > 1);

		my $dn = 'sys/rack-unit-1';
		my $inConfig = {
			computeRackUnit	=> [
				{
					adminPower	=> $op,
					dn		=> $dn,
				},
			],
		};
		my $response = $self->setConfig($inConfig, $dn) or die($@);
		return ($response);
	}
	else {
		return undef;	# didn't do anything
	}
}


=pod

=head2 reboot_machine()

	$cimc->reboot_machine();

Reboots the server.

=cut

sub reboot_machine($) {
	my $self = shift;

	carp("Power cycling $self->{host_addr}.") if ($self->{debug});

	return $self->set_power_mode('cycle-immediate');
}


=pod

=head2 reboot_cimc()

	$cimc->reboot_cimc();

Reboots the CIMC on the server.

=cut

sub reboot_cimc($) {
	my $self = shift;

	carp("Rebooting CIMC on $self->{host_addr}.") if ($self->{debug});

	return $self->set_power_mode('bmc-reset-immediate');
}


=pod

=head2 reset_cmos()

	$cimc->reset_cmos();

Resets the CMOS on the CIMC/server.

NOTE: May require BIOS settings reconfig after this operation.
NOTE: This will power the machine off first.

=cut

sub reset_cmos($) {
	my $self = shift;

	carp("Resetting CMOS on $self->{host_addr}.") if ($self->{debug});

	# We have to be powered off for the following command to work.
	$self->set_power_mode('down');

	return $self->set_power_mode('cmos-reset-immediate');
}


=pod

=head2 send_nmi()

	$cimc->send_nmi();

Sends the host an NMI (diagnostic interrupt).

=cut

sub send_nmi($) {
	my $self = shift;

	carp("Sending $self->{host_addr} an NMI.") if ($self->{debug});

	return $self->set_power_mode('diagnostic-interrupt');
}


=pod

=head2 get_power_budget()

	warn Dumper($cimc->get_power_budget());

=cut

sub get_power_budget($) {
	my $self = shift;

	carp("Getting node power budget info on $self->{host_addr}.") if ($self->{debug});

	my $class = 'powerBudget';

	my $response = $self->getConfigClass($class, 1) or die($@);

	return $response;
}


=pod

=head2 set_power_characterization($$)

	$cimc->set_power_characterization('off');

Sets the power characterization to C<on> (run at boot), C<off> (disabled), or
C<now> (run once now).

NOTE: Running the power characterization routine now will reboot the machine.

=cut

sub set_power_characterization($$) {
	my $self = shift;
	my ($mode) = @_;

	carp("Setting power characterization mode to $mode on $self->{host_addr}.") if ($self->{debug});

	my %opts;
	if ($mode eq 'now') {
		%opts = (
			adminAction	=> 'start-power-char',
		);
	}
	elsif (check_bool($mode)) {
		%opts = (
			runPowCharAtBoot	=> 'yes',
		);
	}
	elsif (!check_bool($mode)) {
		%opts = (
			runPowCharAtBoot	=> 'no',
		);
	}

	my $dn = 'sys/rack-unit-1/budget';
	my $inConfig = {
		powerBudget	=> [
			{
				%opts,
				dn	=> $dn,
			},
		],
	};
	my $response = $self->setConfig($inConfig, $dn) or die($@);

	return $response;
}


=pod

=head2 get_computed_bios_boot_order()

	warn Dumper($cimc->get_computed_bios_boot_order());

Returns the currently computed BIOS boot order.

NOTE: That's generally only computed at boot, so this may need to be rechecked
after a reboot following any updates to the lsboot* nodes that control the
general boot ordering preferences.

=cut

sub get_computed_bios_boot_order($) {
	my $self = shift;

	carp("Getting CIMC computed BIOS boot order on $self->{host_addr}.") if ($self->{debug});

	my $class = 'biosBootDevPrecision';

	my $response = $self->getConfigClass($class, 1) or die($@);

	return $response;
}


=pod

=head2 wait_response($max_wait, &call_back_sub);

	$cimc->wait_response($max_wait, sub { ... });

A generic sub to help with waiting for a condition, as defined by a passed
anonymous subroutine, to be met.

=cut

sub wait_response($$&) {
	my $self = shift;
	my ($max_wait, $sub) = @_;

	my $wait_time =  5;
	my $waited;
	my $condition_met;
	do {
		sleep($wait_time) if (defined($waited));

		if ($self->ping() && $self->login()) {
			$condition_met = &$sub;
		}

		$waited = (defined($waited)) ? $waited + $wait_time : 0;
	} until ($condition_met || $waited >= $max_wait);

	return $condition_met;
}


=pod

=head2 get_firmware_update_status();

	my $response = $cimc->get_firmware_update_status() or die($@);
	warn Dumper($response), ' ';

Returns the status of any currently executing firmware updates.

=cut

sub get_firmware_update_status($) {
	my $self = shift;

	carp("Getting CIMC firmware update status on $self->{host_addr}.") if ($self->{debug});

	my $class = 'huuFirmwareUpdater';

	my $response = $self->getConfigClass($class, 1) or die($@);

	return $response;
}


sub check_firmware_update_status($) {
	my $self = shift;

	my $response = $self->get_firmware_update_status() or die($@);

	if (
		(
			(
				$response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{'updateEndTime'} &&
				!$response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{'updateStartTime'}
			) ||
			(
				$response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{'updateEndTime'} &&
				$response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{'updateStartTime'}
			) ||
			(
				!$response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{'updateEndTime'} &&
				!$response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{'updateStartTime'}
			)
		) && $response->{huuFirmwareUpdater}->[0]->{huuFirmwareUpdateStatus}->[0]->{overallStatus} !~ /progress/i
	) {
		return 1;
	}
	else {
		return 0;
	}
}

=pod

=head2 wait_for_firmware_update_completion();

Attempts to wait for an inprogress firmware update process to complete.

=cut

sub wait_for_firmware_update_completion($) {
	my $self = shift;

	$self->wait_response(2700, sub {
		carp("Waiting for firmware update to complete on $self->{host_addr} ...") if ($self->{debug});

		return $self->check_firmware_update_status();
	}) or croak($@);

	return 1;
}


=pod

=head2 update_firmare(\%opts)

	$cimc->update_firmware({ 
		remoteIp => $remoteHost, 
		remoteShare => $remoteShare, 
		mapType => 'nfs',
	}) or die($@);

Updates the firmware of all components on the CIMC using a firmware update ISO
hosted at a given remote share path.

=cut

sub update_firmware($$) {
	my $self = shift;
	my ($opts) = @_;

	carp("Updating firmware on $self->{host_addr}.") if ($self->{debug});

	my $dn = 'sys/huu/firmwareUpdater';
	my $inConfig = {
		huuFirmwareUpdater	=> [
			{
				dn		=> $dn,
				adminState	=> 'trigger',
				verifyUpdate	=> 'yes',
				stopOnError	=> 'yes',
				updateComponent	=> 'all',
				timeOut		=> TIMEOUT,
				%$opts,
			},
		],
	};
	my $response = $self->setConfig($inConfig, $dn, 1) or die($@);

	# DONE: Wait for success?
	$self->wait_for_firmware_update_completion() or die($@);

	return $response;
}


=pod

=head2 get_firmware_version(;$)

	warn Dumper($cimc->get_firmware_version($force = 1));

Retreives and caches the current firmware version of the CIMC.

=cut

sub get_firmware_version($;$) {
	my $self = shift;
	my ($force) = @_;

	if ($force || !$self->{firmware_version}) {
		carp("Getting CIMC firmware version on $self->{host_addr}.") if ($self->{debug});

		my $dn = 'sys/rack-unit-1/mgmt/fw-system';
		my $response = $self->getConfigDn($dn) or croak($@);
		$self->{firmware_version} = $response->{firmwareRunning}->[0]->{version};
	}

	return $self->{firmware_version};
}


=pod

=head2 compare_firmware_version($$)

	$cimc->compare_firmware_version('>=', '2.0(8d)')
		and warn("CIMC firmware version >= 2.0(8d)");


Performs a version comparison of the current CIMC and the provided value and
comparison function.

=cut

sub compare_firmware_version($$$) {
	my $self = shift;
	my ($op, $to) = @_;

	my $current_firmware_version = $self->get_firmware_version();

	return _compare_firmware_versions($self->{firmware_version}, $op, $to);
}

sub _compare_firmware_versions($$$) {
	my ($ver, $op, $to) = @_;
	# Copied from MySQL version comparison code written ages ago.
	# Accept that it didn't handle alphas in the string ...
	# Hurray, a module that seems to do the trick (Sort::Versions).

	if (!defined($ver)) {
		if ($op eq '<=' || $op eq 'le' || $op eq 'lte') {
			$ver = 0+'inf';
		}
		elsif ($op eq '<' || $op eq 'lt') {
			$ver = 0+'inf';
		}
		elsif ($op eq '>=' || $op eq 'ge' || $op eq 'gte') {
			$ver = 0;
		}
		elsif ($op eq '>' || $op eq 'gt') {
			$ver = 0;
		}
		elsif ($op eq '==' || $op eq 'eq') {
			$ver = 0;
		}
		else {  
			croak("ERROR: Invalid comparison operator: '$op'");
		}
	}

	if (!defined($to)) {
		if ($op eq '<=' || $op eq 'le' || $op eq 'lte') {
			$to = 0+'inf';
		}
		elsif ($op eq '<' || $op eq 'lt') {
			$to = 0+'inf';
		}
		elsif ($op eq '>=' || $op eq 'ge' || $op eq 'gte') {
			$to = 0;
		}
		elsif ($op eq '>' || $op eq 'gt') {
			$to = 0;
		}
		elsif ($op eq '==' || $op eq 'eq') {
			$to = 0;
		}
		else { 
			croak("ERROR: Invalid comparison operator: '$op'");
		}
	}

	my $cmp = versioncmp($ver, $to);

	if ($op eq '<=' || $op eq 'le' || $op eq 'lte') {
		return 1 if ($cmp <= 0);
	}
	elsif ($op eq '<' || $op eq 'lt') {
		return 1 if ($cmp < 0);
	}
	elsif ($op eq '>=' || $op eq 'ge' || $op eq 'gte') {
		return 1 if ($cmp >= 0);
	}
	elsif ($op eq '>' || $op eq 'gt') {
		return 1 if ($cmp > 0);
	}
	elsif ($op eq '==' || $op eq 'eq') {
		return 1 if ($cmp == 0);
	}
	else {  
		croak("ERROR: Invalid comparison operator: '$op'");
	}

	return 0;
}



=pod

=head1 PRIVATE METHODS

=cut

=pod

=head2 _init_lwp_ua(;$)

	$self->_init_lwp_ua();

Internal function for initializing an L<LWP::UserAgent> to C<${addr}:443>.

Optionally accepts a boolean value for whether or not to force a reinitialization.

=cut

sub _init_lwp_ua($;$) {
	my $self = shift;
	my ($force) = @_;

	if ($force || !$self->{lwp_ua}) {
		$self->{lwp_ua} = LWP::UserAgent->new(
			agent		=> 'Cisco::IMC libwww-perl/#.###',
			ssl_opts	=> {
				# Most CICMs are probably going to have self signed certs, 
				# so just ignore the SSL warnings.
				verify_hostname	=> 0,
			},
			# Try to keep the connection open while we make
			# individual requests, mostly just to avoid lots of SSL
			# session start overhead.
			# NOTE: That doesn't actually seem to work unfortunately.
			keep_alive	=> 1,
			timeout		=> TIMEOUT,
		);
	}
	return $self->{lwp_ua};
}


=pod

=head2 _issue_request($$)

	my $request = {
		'configResolveDn'	=> [
			{
				dn		=> $dn,
			},
		],
	};

	my $response = $self->_issue_request($request)
		or die($@);

Converts the given C<$request> to XML via L<XML::Simple> and sends it to the
host via L<LWP::UserAgent> and then parses the result.  If the response is
invalid, an error, or unexpected, it sets C<$@> with an error message and
returns C<undef>, else it returns the resulting XML response as digested by
L<XML::Simple>.

=cut

sub _issue_request($$) {
	my $self = shift;
	my ($request) = @_;
	my $response;

	my $isRetry = 0;
	RETRY:

	# See NOTEs below about XML validation.
	# For now, the poor man's validation is the following assumption/check:
	# There should be only one top level request and it should match the
	# one and only top level response.
	# We also only bother to support a subset of them for the moment.
	my @keys = keys(%{$request});
	if (scalar(@keys) != 1 || !$SUPPORTED_XML{$keys[0]}) {
		croak('ERROR: Invalid request: ', Dumper($request).' ');
	}
	# else
	my $top_level_key = $keys[0];

	# Add the cookie (if it exists) to the request if it wasn't already there.
	if (!$request->{$top_level_key}->[0]->{cookie}) {
		if ($top_level_key !~ /^aaa/) {	# don't loop on ourselves
			$self->_get_auth_cookie();
		}
		$request->{$top_level_key}->[0]->{cookie} = $self->{auth_cookie};
	}

	if (!$self->{xs}) {
		#$self->{xs} = XML::Simple->new(
		$self->{xs} = MyXMLSimple->new(
			RootName	=> undef,
			KeepRoot	=> 1,
			ForceArray	=> 1, 
			ForceContent	=> 1, 
			KeyAttr		=> [],
			#NoSort		=> 1,	# nevermind, use our custom sorting instead
		);
		# NOTE: To self, may instead need to accept raw XML as an input.
	}

	if (!$self->{lwp_ua}) {
		$self->_init_lwp_ua()
			or croak('ERROR: Failed to _init_lwp_ua()!');
	}

	if (!$self->ping()) {
		if (!$isRetry) {
			# Try to re-obtain an auth cookie for requests
			# that may have just taken longer than expected.
			carp("Failed to ping '$self->{host_addr}'.  Attempting to refresh session and retry.") if ($self->{debug});
			$isRetry = 1;
			delete($request->{$top_level_key}->[0]->{cookie});
			sleep(1);
			$self->_init_lwp_ua(1);
			$self->_clear_local_auth_cookie();
			goto RETRY;
		}
		else {
			$@ = "Failed to ping '$self->{host_addr}'.";
			return undef;
		}
	}

	my $url = sprintf('https://%s/nuova', $self->{addr});
	my $xml_request = $self->{xs}->XMLout($request);

	#warn('$url:', Dumper($url), ' ') if ($self->{debug} > 2);
	warn('$request: ', Dumper($request), ' ') if ($self->{debug} > 2);
	warn('$xml_request: ', Dumper($xml_request), ' ') if ($self->{debug} > 3);

	my $http_response = $self->{lwp_ua}->request(POST $url,
		Content_Type	=> 'application/x-www-form-urlencoded',
		Content		=> $xml_request,
	);

	warn('$http_response: ', Dumper($http_response), ' ') if ($self->{debug} > 4);

	if ($http_response->is_success) {
		# NOTE: Might need to handle some decoded_content sorts of things here.
		my $xml_response = $http_response->content();
		warn('$xml_response: ', Dumper($xml_response), ' ') if ($self->{debug} > 3);

		$response = $self->{xs}->XMLin($xml_response);
		warn('$response: ', Dumper($response), ' ') if ($self->{debug} > 2);

		# Check that the response looks ok.

		# NOTE: We could also be doing some sort of XML schema
		# validation, but we aren't currently.  It'd require a little
		# bit of effort to grab and possibly cache the schema files
		# from the nodes as well.
		# Details on where to grab the schemas are here if we want to do that later on:
		# http://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/c/sw/api/2-0/b_Cisco_IMC_api_2_0/b_Cisco_IMC_api_2_0_chapter_0100.html

		# See NOTEs above about top level response checking assumptions.
		@keys = keys(%{$response});
		if (scalar(@keys) != 1 || !$SUPPORTED_XML{$keys[0]}) {
			$@ = "Invalid response from '$self->{host_addr}': ".Dumper($response).' ';
			$response = undef;
		}
		elsif ( $keys[0] eq 'error' 
			&& $response->{'error'}->[0] 
			&& $response->{'error'}->[0]->{response} eq 'yes'
		) {
			$@ = "'".$response->{'error'}->[0]->{errorDescr}."' from '$self->{host_addr}'.";
			$response = undef;
		}
		elsif ($keys[0] ne $top_level_key) {
			$@ = "Unexpected response from '$self->{host_addr}': ".Dumper($response).' ';
			$response = undef;
		}
		else {
			if ($response->{$top_level_key}->[0]
				&& !$isRetry
				&& $top_level_key !~ /^aaa/
				&& $response->{$top_level_key}->[0]->{response} eq 'yes'
				&& $response->{$top_level_key}->[0]->{errorCode}
				&& $response->{$top_level_key}->[0]->{errorCode} eq '552'
				&& $response->{$top_level_key}->[0]->{errorDescr}
				&& $response->{$top_level_key}->[0]->{errorDescr} eq 'Authorization required'
			) {
				# Try to re-obtain an auth cookie for requests
				# that may have just taken longer than expected.
				carp("Session error encountered while talking to '$self->{host_addr}'.  Attempting to refresh session and retry.") if ($self->{debug});
				$isRetry = 1;
				delete($request->{$top_level_key}->[0]->{cookie});
				sleep(1);
				$self->_init_lwp_ua(1);
				$self->_clear_auth_cookie();
				goto RETRY;
			}

			if ($response->{$top_level_key}->[0]
				&& $response->{$top_level_key}->[0]->{response} eq 'yes' 
				&& !$response->{$top_level_key}->[0]->{errorCode}
			) {
				# Assume success and let the caller parse the rest of the results.

				# To try and print warnings and status messages though.
				if ($self->{debug} && $response->{$top_level_key}->[0]->{outStatus}) {
					carp($response->{$top_level_key}->[0]->{outStatus})
						unless ($top_level_key eq 'aaaLogout');
				}
			}
			else {
				$@ = "'".$response->{$top_level_key}->[0]->{errorDescr}."' from '$self->{host_addr}'.";
				$response = undef;
			}
		}
	}
	else {
		if (!$isRetry) {
			# Try to re-obtain an auth cookie for requests
			# that may have just taken longer than expected.
			carp("HTTP error encountered while talking to '$self->{host_addr}'.  Attempting to refresh session and retry.") if ($self->{debug});
			$isRetry = 1;
			delete($request->{$top_level_key}->[0]->{cookie});
			sleep(1);
			$self->_init_lwp_ua(1);
			# In this case we can't actually use the usual subs since
			# they also use _issue_request() which causes the
			# $isRetry variable to constantly be reset to 0 thus
			# causing an infinite loop.  Serves me right for using
			# goto statements :P
			#$self->_get_auth_cookie(1);
			$self->_clear_local_auth_cookie();
			goto RETRY;
		}
		$@ = "'".$http_response->status_line."' from '$self->{host_addr}'.";
		$response = undef;
	}

	# DONE: Make the (internal) caller strip off the top level before
	# returning it to the actual (client) caller?  	Yes.
	return $response;
}


=pod

=head2 _get_auth_cookie(;$)

	$self->_get_auth_cookie();

Internal function for obtaining an authentication session cookie from the CICM.

Will attempt to return an existing valid cookie by default.

Optionally accepts a boolean value for whether or not to force a new session,
which will also implicitly attemp to cleanup existing ones that are still
valid.

=cut

sub _get_auth_cookie($;$) {
	my $self = shift;
	my ($force) = @_;

	my $now = time();
	my $request;

	if ($force || !$self->{auth_cookie} || $self->{auth_cookie_valid_until} < $now) {
		$self->_clear_auth_cookie();
		$@ = undef;	# ignore any error result

		$request = {
			aaaLogin	=> [
				{
					inName		=> $self->{user},
					inPassword	=> $self->{password},
				},
			],
		};
	}
	elsif ($self->{auth_cookie} && $self->{auth_cookie_valid_until} < $now + TIMEOUT) {
		# Refresh the cookie before it expires or we timeout.
		$request = {
			aaaRefresh	=> [
				{
					inCookie	=> $self->{auth_cookie},
					inName		=> $self->{user},
					inPassword	=> $self->{password},
				},
			],
		};
	}

	if ($request) {
		my $response = $self->_issue_request($request);

		$self->{auth_cookie} = $response->{aaaLogin}->[0]->{outCookie} 
			if ($response->{aaaLogin}->[0]->{outCookie});
		$self->{auth_cookie_valid_until} = $now + $response->{aaaLogin}->[0]->{outRefreshPeriod} 
			if ($response->{aaaLogin}->[0]->{outRefreshPeriod});

		## Clear firmware_version cache.
		#$self->{firmware_version} = undef;
	}

	return $self->{auth_cookie};
}


sub _clear_local_auth_cookie($) {
	my $self = shift;
	
	$self->{auth_cookie} = undef;
	$self->{auth_cookie_valid_until} = 0;
}


=pod

=head2 _clear_auth_cookie()

	$self->_clear_auth_cookie();

Internal function for clearing an authentication session from the CICM.

=cut

sub _clear_auth_cookie($;$) {
	my $self = shift;
	#my ($force) = @_;

	my $now = time();

	if ($self->{auth_cookie} && $self->{auth_cookie_valid_until} > $now) {
		my $request = {
			aaaLogout	=> [
				{
					inCookie	=> $self->{auth_cookie},
				},
			],
		};
		eval {
			$self->_issue_request($request);
		};	# don't really care about the response
		if ($@) {
			warn($@) if ($self->{debug});
		}
	}

	$self->_clear_local_auth_cookie();
}



=pod

=head1	FUNCTIONS

=cut


=pod

=head2 check_bool($)

Checks a boolean value for a true or false value in a handful of ways.

=cut

sub check_bool($) {
	my ($bool) = @_;

	if (defined($bool)) {
		return ($bool && $bool !~ /^(0|off|false|no|inactive|disabled)$/) ? 1 : 0;
	}
	else {
		return undef;
	}
}


=pod

=head2 get_host_addr_string($$)

Returns a user friendly version of $host and/or $addr for printing.

=cut

sub get_host_addr_string($$) {
	my ($host, $addr) = @_;
	my ($name, $domain) = split(/[.]/, $addr, 2);
	if ($name eq $host) {
		return $host;	# short names match, just use that
	}
	elsif ($host eq $addr) {
		return $addr;	# they're the same, just use that
	}
	else {	# else, show both
		return $host.'['.$addr.']';
	}
}

1;
