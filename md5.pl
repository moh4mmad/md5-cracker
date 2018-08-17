use Digest::MD5 qw(md5_hex);
use Time::HiRes qw(gettimeofday);

if($ARGV[0]=~"a"){
$pass = "abcdefghijklmnopqrstuvwxyz";
}
if($ARGV[0]=~"A"){
$pass = $pass. "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
}
if($ARGV[0]=~"n"){
$pass = $pass."1234567890";
}
if ($ARGV[0]=~"s"){
$pass = $pass. "!\"\$%&/()=?-.:\\*'-_:.;,";
}

if($pass eq "" or $ARGV[3] eq "") {usage();};

if (length($ARGV[3]) != 32) { die "Sorry but it seems that the MD5 is not valid!\n";};

print "Selected charset for attack: '$pass\'\n";

print "Going to Crack '$ARGV[3]'...\n";

for (my $t=$ARGV[1];$t<=$ARGV[2];$t++){
crack ($t);
}

sub usage{
print "\n";
print " #############################################################################\n";
print " #                                                                           #\n";
print " # Usage: ./md5.pl <select option> <minlen> <maxlan> <MD5>                   #\n";
print " # Character options: a - small letters # a,b,c                              #\n";
print " #                    A - big letters   # A,B,C                              #\n";
print " #                    n - numbers       # 1,2,3                              #\n";
print " #                    s - symbols       # !,#,@                              #\n";
print " # Example: ./md5.pl an 1 3 1bc29b36f623ba82aaf6724fd3b16718                 #\n";
print " #                                                                           #\n";
print " #############################################################################\n";
sys.exit(1)
}



sub crack{
$check = 1;
$CharSet = shift;
@RawString = ();
for (my $i =0;$i<$CharSet;$i++){ $RawString[i] = 0;}
$Start = gettimeofday();
do{
  for (my $i =0;$i<$CharSet;$i++){
   if ($RawString[$i] > length($pass)-1){
    if ($i==$CharSet-1){
    print "Bruteforcing done with $CharSet Chars. No Results.\n";
    $cnt=0;
    return false;
   }
   $RawString[$i+1]++;
   $RawString[$i]=0;
   }
  }

   $ret = "";
   for (my $i =0;$i<$CharSet;$i++){ $ret = $ret . substr($pass,$RawString[$i],1);}
   $hash = md5_hex($ret);
   $cnt++;
   $Stop = gettimeofday();
   if ($Stop-$Start>$check){
    $cnt = int($cnt/$check);
    print "$cnt hashes\\second.\tLast Pass '$ret\'\n";
    $cnt=0;
    $Start = gettimeofday();
   }
   print "$ARGV[3] != $hash ($ret)\n";
   if ($ARGV[3] eq $hash){
    die "\nPassword Cracked! => $ret\n";
   }
  $RawString[0]++;
}while($RawString[$CharSet-1]<length($pass));
}
