<?php
include 'vendor/autoload.php';

use Web3p\RLP\RLP;

$rlp = new RLP;


// c483646f67
$encoded = $rlp->encode([1274420, 1191326200,55000,'0xd88b51f4e67b0707f6a38db20baf06ccaf6fd3f0',358728000000000000,0]);
//print_r(hash('sha256',$encoded));
// 83646f67
//$encoded = $rlp->encode('10E01854E3B29200825208950xc390cC49a32736a58733Cf46bE42f734dD4f53cb88DE0B6B3A764000001');

$decoded = $rlp->decode('0x' . '0xeb831372358447406c7082d6d894b9684af737d032a5f58741d512cdb4f8b3b632028801cdda4faccd000080');
//print_r($decoded);
//print_r(hash('sha256','10E01854E3B29200825208950xc390cC49a32736a58733Cf46bE42f734dD4f53cb88DE0B6B3A764000001'));
 $gx = '55066263022277343669578718895168534326250603453777594175500187360389116729240';
 $r1 = '8896428005433108346438698031729412187275695101650896644816899000848604228975';
 $s1 = '45794414965046146255251218796780847619051721133833274362794706797574315245129';
 $e1 = '46436640360489318594341940301969422692854193638053355274678287597874163123995';
/*$j=1;
 for($i=1;$i<=100000000000000000000000000000000000000000000000000000000000000000000000000000;$i=bcadd($i,$j)){
    //01000000a0d4ea3416518af0b238fef847274fc768cd39d0dc44a0ea5ec0c2dd000000007edfbf7974109f1fd628f17dfefd4915f217e0ec06e0c74e45049d36850abca4 bc0eb049 ffff001d 27d0031e 0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d024f02ffffffff0100f2052a010000004341048a5294505f44683bbc2be81e0f6a91ac1a197d6050accac393aad3b86b2398387e34fedf0de5d9f185eb3f2c17f3564b9170b9c262aa3ac91f371279beca0cafac00000000
     
    $k1 = bcadd('194219999999999999999999999900000000000000000000000000000000000',$i);
    print_r($k1."\r\n");
    $p = bcsub(bcdiv(bcmul($s1,$k1),$r1),bcdiv($e1,$r1));
    print_r($p."\r\n");
    print_r(bcdechex($p)."\r\n");
    print_r(strlen(bcdechex($p))."\r\n");
    print_r($i."\r\n");

    if(strlen(bcdechex($p))==64){
        break;
    }else{
        $j=bcmul($j,2);
    }
 }*/
 /*$k1 = '1405924699393950650705035035648194463064496908512739764938914210840487641761';
 $j=0;
 for($i=$k1;$i>1;$i=bcsub($k1,1)){
    //01000000a0d4ea3416518af0b238fef847274fc768cd39d0dc44a0ea5ec0c2dd000000007edfbf7974109f1fd628f17dfefd4915f217e0ec06e0c74e45049d36850abca4 bc0eb049 ffff001d 27d0031e 0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d024f02ffffffff0100f2052a010000004341048a5294505f44683bbc2be81e0f6a91ac1a197d6050accac393aad3b86b2398387e34fedf0de5d9f185eb3f2c17f3564b9170b9c262aa3ac91f371279beca0cafac00000000
     
    //$k1 = bcadd('194219999999999999999999999900000000000000000000000000000000000',$i);
    $k1 = bcsub($k1,'18');
    print_r($k1."\r\n");
    $p = bcsub(bcdiv(bcmul($s1,$k1),$r1),bcdiv($e1,$r1));
    print_r($p."\r\n");
    print_r(bcdechex($p)."\r\n");
    print_r(strlen(bcdechex($p))."\r\n");
    $j=$j+1;
    print_r($j."\r\n");
    if(strlen(bcdechex($p))==63){
        break;
    }
 }*/
 
 $k1 = '1405924699393950650705035035648194463064496908512739764938914210840487641599';
 $j=0;
 for($i=1;$i<=100000000000000000000000000000000000000000000000000000000000000000000000000000;$i=bcadd($k1,1)){
    //01000000a0d4ea3416518af0b238fef847274fc768cd39d0dc44a0ea5ec0c2dd000000007edfbf7974109f1fd628f17dfefd4915f217e0ec06e0c74e45049d36850abca4 bc0eb049 ffff001d 27d0031e 0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d024f02ffffffff0100f2052a010000004341048a5294505f44683bbc2be81e0f6a91ac1a197d6050accac393aad3b86b2398387e34fedf0de5d9f185eb3f2c17f3564b9170b9c262aa3ac91f371279beca0cafac00000000
     
    //$k1 = bcadd('194219999999999999999999999900000000000000000000000000000000000',$i);
    $k1 = bcadd($k1,'1');
    print_r($k1."\r\n");
    $p = bcadd(bcdiv(bcmul($s1,$k1),$r1),bcdiv($e1,$r1));
    print_r($p."\r\n");
    print_r(bcdechex($p)."\r\n");
    print_r(strlen(bcdechex($p))."\r\n");
    $j=$j+1;
    print_r($j."\r\n");
    if(strlen(bcdechex($p))==64){
        break;
    }
 }

  function bcdechex($dec) {
    $hex = '';
    do {    
        $last = bcmod($dec, 16);
        $hex = dechex($last).$hex;
        $dec = bcdiv(bcsub($dec, $last), 16);
    } while($dec>0);
    return $hex;
}


function bchexdec($hex)
{
    $dec = 0;
    $len = strlen($hex);
    for ($i = 1; $i <= $len; $i++) {
        $dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
    }
    return $dec;
}



/*print_r($init."\r\n");
$p = bcsub(bcdiv(bcmul($s1,$init),$r1),bcdiv($e1,$r1));
print_r($p."\r\n");
print_r(bcdechex($p)."\r\n");
print_r(strlen($p)."\r\n");
print_r($i."\r\n");
$init = bcadd($init,1);*/
 $r2 = '72475776527602912050506649266909205764927076929153236762205089438279560007196';
 $s2 = '34251837620193840812070615154472980308374389020885414000199683391217848973871';
 $e2 = '34521213173032599819048688323489123163706397621175535348701163595305762228827';
 //$k = ($e1-$e2)/($s1-$s2);
 //print_r($k);

 $f = $e2/$s2;
 $d = $r2*$s1/($r1*$s2);
 $g = $r2*$e1/($r1*$s2);
 $x = ($f-$g)/(1-$d);
 
 /*$x = bcmul($x,'10000000000000000000000000000000000000000000000000000000000000000000000000000');

 $p = bcsub(bcdiv(bcmul($s1,$x),bcmul($r1,'10000000000000000000000000000000000000000000000000000000000000000000000000000')),bcdiv($e1,bcmul($r1,'10000000000000000000000000000000000000000000000000000000000000000000000000000')));
 print_r($x."\r\n");
 print_r($p."\r\n");
 print_r(bcdechex($p));*/
 
 function bcdechex($dec) {
    $hex = '';
    do {    
        $last = bcmod($dec, 16);
        $hex = dechex($last).$hex;
        $dec = bcdiv(bcsub($dec, $last), 16);
    } while($dec>0);
    return $hex;
}


function bchexdec($hex)
{
    $dec = 0;
    $len = strlen($hex);
    for ($i = 1; $i <= $len; $i++) {
        $dec = bcadd($dec, bcmul(strval(hexdec($hex[$i - 1])), bcpow('16', strval($len - $i))));
    }
    return $dec;
}



//echo(bchexdec($r1));