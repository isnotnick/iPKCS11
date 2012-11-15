use pkcs11_constants;
use Crypt::OpenSSL::RSA;
use Crypt::OpenSSL::Bignum;
use File::Slurp;
use strict;

our $keyNameList = {};

my $KEYDIR = "./KEYS";
my @list = `grep -l "BEGIN RSA PRIVATE KEY" $KEYDIR/*|while read priv; do if [ -e "\$priv.pem" ]; then if grep -q "BEGIN RSA PUBLIC KEY" "\$priv.pem"; then echo \$priv;fi;fi ;done`;

my $c = 1337;
for(@list)
{
    chop;
    $keyNameList->{$c++} = $_;
}

sub C_GetInfo {
    # my $params = shift;
    # no params to parse

    my $reply = {
        'libraryDescription' => "Perl JSON PKCS Module           ",
        'manufacturerID'     => "Fiction Force TM                ",
        'flags'              => 0,
        'cryptokiVersion'    => {'major' => 1, 'minor' => 9},
        'libraryVersion'     => {'major' => 2, 'minor' => 3},
        'returnCode'         => CKR_OK
    };

    return $reply;
}


sub C_GetSlotList
{
    # my $params = shift;
    # no params to parse

    my $reply = {
        'slotList'   => [map(int($_), keys %$keyNameList)],
        'returnCode' => CKR_OK
    };

    return $reply;
}

sub C_GetTokenInfo
{
    my $params = shift;
    my $slotID = $params->{'slotID'};
    my $hSession = $slotID;

    my $filename = $keyNameList->{$hSession};
    $filename =~ /([^\/]*)$/;
    my $label = "passphrase for $1";
    $label = $label . " "x(32 - length($label));

    

    my $reply = {
        'label'                 => $label,
        'manufacturerID'        => "Manne Manne Manne               ",
        'model'                 => "PKCS#15 emulated",
        'serialNumber'          => "CAFEBABE,B0BDEAD",
        'flags'                 => CKF_RNG | CKF_WRITE_PROTECTED | CKF_LOGIN_REQUIRED | CKF_USER_PIN_INITIALIZED | CKF_TOKEN_INITIALIZED | CKF_USER_PIN_LOCKED,
        'ulMaxSessionCount'     => 0,
        'ulSessionCount'        => 0,
        'ulMaxRwSessionCount'   => 0,
        'ulRwSessionCount'      => 0,
        'ulMaxPinLen'           => 32,
        'ulMinPinLen'           => 0,
        'ulTotalPublicMemory'   => -1,
        'ulFreePublicMemory'    => -1,
        'ulTotalPrivateMemory'  => -1,
        'ulFreePrivateMemory'   => -1,
        'hardwareVersion'       => {'major' => 1, 'minor' => 9},
        'firmwareVersion'       => {'major' => 1, 'minor' => 9},
        'utcTime'               => "                ",
        'returnCode'            => CKR_OK
    };

    return $reply;
}

our $RSAList = {};
sub C_OpenSession
{
    my $params = shift;
    my $slotID = $params->{'slotID'};
    my $hSession = $slotID;
    my $id = $hSession;

    my $public_key = $keyNameList->{$id} . ".pem";
    my $key_string = read_file($public_key);
    my $rsa = Crypt::OpenSSL::RSA->new_public_key($key_string);

    my $reply;
    if($rsa) 
    {  
        $RSAList->{$id}->{'public'} = $rsa;
        $reply = {
            'hSession'   => $hSession,
            'returnCode' => CKR_OK
        };
    }
    else
    {
        $reply = {
            'hSession'   => $hSession,
            'returnCode' => CKR_KEY_UNEXTRACTABLE
        };
    }

    return $reply;
}

our $object_count;
sub C_FindObjectsInit
{
    $object_count = 1;
    my $reply = {
        'returnCode'     => CKR_OK
    };

    return $reply;
}

sub C_FindObjects
{
    my $reply = {
        'ulObjectCount'  => $object_count--,
        'returnCode'     => CKR_OK
    };

    return $reply;
}

sub C_FindObjectsFinal
{
    my $reply = {
        'returnCode'     => CKR_OK
    };

    return $reply;
}

sub C_GetAttributeValue
{
    my $params   = shift;
    my $hSession = int($params->{'hSession'});
    my $ulCount  = int($params->{'ulCount'});
    if($ulCount != 3)
    {
	print "DEBUG: not implemented: ulCount = $ulCount\n";
        my $reply = {
            'returnCode' => CKR_ARGUMENTS_BAD
        };
        return $reply;
    }
    
    my $rsa = $RSAList->{$hSession}->{'public'};
    my ($rn, $re, $rd, $rp, $rq, $rdmp1, $rdmq1, $riqmp) = $rsa->get_key_parameters;
    my $modulus = $rn->to_hex;

    my $reply = {
        'template'  =>
        [
            {
                'type'       => CKA_ID,
                'value'      => 0x03
            },
            {
                'type'       => CKA_MODULUS,
                'value'      => $modulus
            },
            {
                'type'       => CKA_PUBLIC_EXPONENT,
                'value'      => 0x10001
            },
        ],
        'returnCode' => CKR_OK
    };
    
    return $reply;
}

sub C_Login
{
    my $params     = shift;
    my $hSession   = int($params->{'hSession'});
    my $passphrase = $params->{'pin'};
    my $reply;

    #print "hSession=$hSession, passphrase=$passphrase\n";

    my $private_key = $keyNameList->{$hSession};
    #my $key_string = read_file($private_key);
    my $key_string = `openssl rsa -inform PEM -in $private_key -passin pass:$passphrase 2> /dev/null`;
    if($? != 0)
    {
        $reply = {
            'returnCode' => CKR_KEY_UNEXTRACTABLE
        };
        return $reply;
    }

    my $rsa = Crypt::OpenSSL::RSA->new_private_key($key_string);

    if($rsa)
    {
        $RSAList->{$hSession}->{'private'} = $rsa;
        $reply = {
            'returnCode' => CKR_OK
        };
    }
    else
    {
        $reply = {
            'returnCode' => CKR_KEY_UNEXTRACTABLE
        };
    }
    return $reply;
}

sub C_SignInit
{
    my $reply = {
        'returnCode' => CKR_OK
    };
    return $reply;
}

sub C_Sign
{
    my $params   = shift;
    my $hSession = $params->{'hSession'};
    my $hexmsg   = $params->{'data'};

    my $msg = pack('H*', $hexmsg);
    my $rsa = $RSAList->{$hSession}->{'private'};

    $rsa->use_sha1_hash();
    $rsa->use_pkcs1_padding();
    my $signature = $rsa->private_encrypt($msg);
    my $hexsig = unpack('H*', $signature);

    my $reply = {
        'signature'  => $hexsig,
        'returnCode' => CKR_OK
    };
    return $reply;
}

sub C_CloseSession
{
    my $params   = shift;
    my $hSession = $params->{'hSession'};
    undef $RSAList->{$hSession};

    my $reply = {
        'returnCode' => CKR_OK
    };
    return $reply;
}

sub C_Finalize
{
    my $reply = {
        'returnCode' => CKR_OK
    };
    return $reply;
}

1;
