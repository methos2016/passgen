program passgen;

(* --------------------------------------------------------------------------------

   passgen is a program that generates random password

   -------------------------------------------------------------------------------- *)

uses
  SysUtils, math;

type
  pstring = ^string;

  TCLIOptions = record
                  long   : string;    // long option
                  short  : string;    // short option
                  proc   : procedure; // procedure to be executed
                  present: boolean;   // is option present in command given?
                end;

const
  sl     = #10;
  dl     = sl+sl;
  stdin  = 0;
  stdout = 1;
  stderr = 2;

const
  PROGRAM_OPTIONS_COUNT = 7;
  PROGRAM_NAME          = 'passgen';
  PROGRAM_TASK          = 'generate random passwords.';
  WORD_SEPARATOR        = {$I %WORD_SEPARATOR%};
  RANDOM_DATA_SIZE      = 8192;
  DICT_COUNT            = 6;
  TABLE_1_SIZE          = 256;
  TABLE_2_SIZE          = 256;
  TABLE_3_SIZE          = 256;
  TABLE_4_SIZE          = 256;
  TABLE_5_SIZE          = 1024;
  TABLE_6_SIZE          = 1024;

var
  fd0         : sizeint;
  rdata       : ^word;
  exe_name    : string;
  exe_dir     : string;
  work_dir    : string;
  pcount      : sizeint;
  array0_count: sizeint;
  array0      : packed array of string;
  quiet       : boolean = false;





(* ***************************************************************************

   get_options() retrieves all options and flags them as present or not

   *************************************************************************** *)
procedure get_options(var options: array of TCLIOptions);
var
  lpp0, lpp1: integer;
begin
  if (ParamCount() = 0) or (Length(options) = 0) then
    exit;


  // loop through available options
  for lpp0 := 0 to Length(options)-1 do
  begin
    // loop through given options, check if any given match the current
    for lpp1 := 1 to ParamCount() do
    begin
      options[lpp0].present := false;

      if (ParamStr(lpp1) = options[lpp0].short) or (ParamStr(lpp1) = options[lpp0].long) then
      begin
        options[lpp0].present := true;

        break;
      end;
    end;
  end;
end;





procedure show_header();
begin
  Write({$I %LOCAL_DATE%},sl);
  Write(PROGRAM_NAME,' is a program to ',PROGRAM_TASK,dl);

  Write('SHA256: ',{$I %SOURCE_HASH%},dl);
end;





procedure show_help();
begin
  show_header();

  Write('Usage:',sl);
  Write('Generate a random password:',sl);
  Write('  ',exe_name,' <password_length> <dictionary_id> [extra_options]',sl);
  Write('    Example: ',exe_name,' 16 3 -q',dl);

  Write('Generate a random password of variable length:',sl);
  Write('  ',exe_name,' <minimum_length>-<maximum_length> <dictionary_id> [extra_options]',sl);
  Write('    Example: ',exe_name,' 15-25 3 -q',dl);

  Write('Generate a random password from a custom dictionary:',sl);
  Write('  ',exe_name,' <password_length> 0 [extra_options] < <input_file_from_stdin>',sl);
  Write('    Example: ',exe_name,' 16 0 -q < /etc/chars.txt',dl);
  Write('  Note: Input data must be UTF-8 encoded and each character/word must be separated by a new line',dl);

  Write('Additional options:',sl);
  Write('  --quiet,                                       -q: Keeps output to a minimum. Only show generated password.',sl);
  Write('  --word,                                        -w: It is a word dictionary, separate each word with a space.',sl);
  Write('  --hex-to-word <hex_value> <dict_index>,      -h2w: Convert hexadecimal number to word(s).',sl);
  Write('  --word-to-hex <word1:word2...> <dict_index>, -w2h: Convert word(s) to hexadecimal number.',sl);
  Write('  --writing-mode                                 -p: Prints password character by character. Press ENTER to show next character.',sl);
  Write('  --entropy <string>                             -e: Calculates real entropy of given password and rates it.',sl);
  halt(-1);
end;





procedure fatal_error(message: string);
begin
  WriteLn(message);

  halt(-1);
end;





procedure print_unique(const list: pstring; const count: sizeuint);
// print unique characters for given list
var
  lpp0, lpp1: sizeuint;
  temp      : array of string;
  unique    : boolean;
begin
  if count < 1 then exit;

  SetLength(temp, 1);

  temp[0] := list[0];


  for lpp0 := 0 to count-1 do
  begin
    unique := true;


    // check if we already have it...
    for lpp1 := 0 to Length(temp)-1 do
    begin
      if list[lpp0] = temp[lpp1] then unique := false;
    end;


    if unique then
    begin
      SetLength(temp, Length(temp)+1);

      temp[Length(temp)-1] := list[lpp0];
    end;
  end;


  for lpp0 := 0 to Length(temp)-1 do WriteLn(temp[lpp0]);


  SetLength(temp, 0);
end;





procedure seq();
var
  lpp0: sizeint;
begin
  // generate sequence of chars
  for lpp0 := $20 to $7E do
    Write(char(lpp0));

  halt(0);
end;





procedure set_quiet_mode();
begin
  quiet := true;
end;

var
  {$I ./dict_1.pasinc}
  {$I ./dict_2.pasinc}
  {$I ./dict_3.pasinc}
  {$I ./dict_4.pasinc}
  {$I ./dict_5.pasinc}
  {$I ./dict_6.pasinc}
  {$I ./dict.pasinc}
  pwcfile  : file of byte;
  passchars: string;

var
  options : array[0..PROGRAM_OPTIONS_COUNT-1] of TCLIOptions = ( (long:'--help'; short:'-h'; proc:@show_help; present:false),
                                                                 (long:'--quiet'; short:'-q'; proc:@set_quiet_mode; present:false),
                                                                 (long:'--word'; short:'-w'; proc:nil; present:false),
                                                                 (long:'--hex-to-word'; short:'-h2w'; proc:nil; present:false),
                                                                 (long:'--word-to-hex'; short:'-w2h'; proc:nil; present:false),
                                                                 (long:'--writing-mode'; short:'-p'; proc:nil; present:false),
                                                                 (long:'--entropy'; short:'-e'; proc:nil; present:false)
                                                               );





procedure entropy_get(password: string);
// this procedure calculates real entropy of given password and rates it (0-6)
const
  OPINION_TEXT = 'This password is ';
  OPINION_NOTE = 'Note: This opinion is valid only if the given password was randomly generated.';
var
  chars_in_password: array of char;
  rate             : byte;
  rating           : array[0..6] of string = ('VERY WEAK', 'WEAK', 'STILL WEAK', 'ALMOST STRONG', 'STRONG', 'VERY STRONG', 'INSANE');
  bits             : array[0..6] of single = (0, 12, 32, 96, 128, 224, 384);
  bits_password    : single;
  unique           : boolean;
  // loop
  lpp0, lpp1: sizeuint;
label
  _rate;
begin
  if Length(password) <= 0 then
  begin
    rate := 0;

    bits_password := 0;

    goto _rate;
  end;



  // set first char, we know the given password will have at least 1 unique char
  SetLength(chars_in_password, Length(chars_in_password)+1);

  chars_in_password[Length(chars_in_password)-1] := password[lpp0+1];



  // search for more chars
  for lpp0 := 1 to Length(password)-1 do
  begin
    unique := true;


    for lpp1 := 0 to Length(chars_in_password)-1 do
    begin
      // check for uniqueness...
      if password[lpp0+1] = chars_in_password[lpp1] then
      begin
        unique := false;

        break;
      end;
    end;


    if unique then
    begin
      SetLength(chars_in_password, Length(chars_in_password)+1);

      chars_in_password[Length(chars_in_password)-1] := password[lpp0+1];
    end;
  end;


  // calculate entropy on given password
  bits_password := log2(Length(chars_in_password)) * Length(password);


  // rate it
  for lpp0 := 0 to Length(rating)-1 do
  begin
    if lpp0 < 6 then
    begin
      if (bits_password >= bits[lpp0]) and (bits_password < bits[lpp0+1]) then
      begin
        rate := lpp0;

        break;
      end;
    end
  else
    begin
      if (bits_password >= bits[lpp0]) then
      begin
        rate := lpp0;

        break;
      end;
    end;
  end;


_rate:
  // give opinion on password and print its info
  WriteLn(OPINION_TEXT+rating[rate]+'!',dl);

  WriteLn('Password length : ',Length(password));
  WriteLn('Password entropy: ',FloatToStrF(bits_password,ffFixed,9999,2),' bits.',dl);

  WriteLn(OPINION_NOTE);


  halt(0);
end;





procedure hex_to_words(const input: string; dict: pstring);
// This procedure converts a hexadecimal sequence to words
var
  len  : sizeint;
  value: word;
  words: string;
  count: sizeint;
  lpp0 : sizeint;
  // temp variables
  str0: string;
  tmp0: word;
begin
  len := Length(input);

  words := '';

  if len < 1 then
    fatal_error('Invalid input.');

  if len <= 3 then
  begin
    // represents just 1 word
    value := 0;

    val('$'+input, value, tmp0);

    if value >= 1024 then
      fatal_error('Index out of range.');

    words := dict[value];

    Write(words, sl);
  end
else
  begin
    // must be divisible by 3
    if (len mod 3) <> 0 then
      fatal_error('Invalid input.');

    count := len div 3;

    for lpp0 := 0 to count-1 do
    begin
      str0 := pchar(input)[lpp0*3..(lpp0*3)+2];

      value := 0;

      val('$'+str0, value, tmp0);

      if value >= 1024 then
        fatal_error('Index out of range.');

      if lpp0 < count-1 then
      begin
        words := dict[value];

        Write(words,#32);
      end
    else
      begin
        words := dict[value];

        Write(words,sl);
      end;
    end;
  end;

  halt(0);
end;





function words_to_hex_get_count(input: pchar): sizeint;
// This procedure get count of words in command "word1:word2..."
var
  lpp0: sizeint;
begin
  words_to_hex_get_count := 0;

  for lpp0 := 0 to Length(input)-1 do
  begin
    if input[lpp0] = ':' then inc(words_to_hex_get_count);
  end;

  if words_to_hex_get_count >= 0 then
    inc(words_to_hex_get_count);
end;





procedure words_to_hex_get_words(input: pchar; count: sizeint; out output: array of string);
// This procedure organizes all words given in command line in an array of string
function get_current_len(curpos: sizeint; size: sizeint): sizeint;
begin
  get_current_len := 0;

  repeat
    inc(get_current_len);
  until (input[curpos+get_current_len] = ':') or (curpos+get_current_len >= size);
end;
var
  lpp0: sizeint;
  pos1: sizeint;
  len2: sizeint;
  len : sizeint;
begin
  pos1 := 0;
  len  := Length(input);

  for lpp0 := 0 to count-1 do
  begin
    len2 := get_current_len(pos1, len);

    output[lpp0] := input[pos1..pos1+len2-1];

    inc(pos1, len2);
    // skip separator char
    inc(pos1);
  end;
end;





procedure words_to_hex(input: array of string; word_count: sizeint; dict: pstring);
// This procedure converts a sequence of words to a hexadecimal number
var
  hex : string;
  lpp1: sizeint;
  lpp0: sizeint;
  // temp variables
  found: boolean;
begin
  found := false;

  lpp1 := 0;


  repeat
    for lpp0 := 0 to 1024-1 do
    begin
      if dict[lpp0] = input[lpp1] then
      begin
        found := true;

        break;
      end;
    end;


    if not found then
      fatal_error('Word "'+input[lpp0]+'" is not present in dictionary.');


    inc(lpp1);

    dec(word_count);


    Write(HexStr(lpp0, 3));
  until word_count = 0;

  Write(sl);

  halt(0);
end;





procedure generate_password_from_table(table: pstring; const maxindex: sizeint; table_length: sizeint);
// "limit" is mask to limit table index size, if a table only holds 1 byte "limit" must be $00FF...
// for this reason TABLE_SIZE must be bit aligned (or power of two-1)

  procedure nested_randomize_table();
  var
    chosen       : integer;
    count        : integer;
    temp_array   : array of string;
    lpp0, lpp1, a: integer;
  begin
    count := table_length;

    SetLength(temp_array, table_length);


    for lpp0 := 0 to table_length-1 do
      temp_array[lpp0] := table[lpp0];


    // randomize character table
    for lpp0 := 0 to table_length-1 do
    begin
      // gets a random number from 0 to count-1
      chosen := Random(count);

      table[lpp0] := temp_array[chosen];

      // exclude chosen item from "temp_array"
      temp_array[chosen] := '';


      // copy all array but avoid chosen item, so it can't be chosen again
      lpp1 := 0;
      a    := 0;

      repeat
        if temp_array[lpp1+a] <> '' then
        begin
          temp_array[lpp1] := temp_array[lpp1+a];

          inc(lpp1);
        end
      else
        begin
          inc(a);
        end;
      until lpp1 = count-1;


      dec(count);
    end;


    SetLength(temp_array, 0);
  end;

var
  lpp0    : sizeint;
  passlen : sizeint; // length of password
  password: string;  // the password generated
  union   : string;  // word separator
  limit   : word;    // maximum possible array index bit mask, must be "bit aligned" (or power of two-1) (e.g.: %00001111, %00000011, %00111111, %11111111)
  min, max: integer; // minimum/maximum password length, if specified 'x-x'
  temp    : string;
  padlen  : qword;
  ctable  : packed array of string; // used for custom table, if dict_id is 0
begin
  if not Assigned(table) then
  begin
    // load dictionary from stdin
    repeat
      ReadLn(temp);


      if temp <> '' then
      begin
        SetLength(ctable, Length(ctable)+1);

        ctable[Length(ctable)-1] := temp;
      end;
    until eof(Input);


    padlen := Length(ctable);


    if (frac(log2(Length(ctable))) <> 0) or (log2(Length(ctable)) < 1) then
    begin
      // pad dictionary/word or char list to nearest power of two
      padlen := %0100000000000000000000000000000000000000000000000000000000000000;

      for lpp0 := (sizeof(padlen) * 8)-2 downto 0 do
      begin
        if (Length(ctable) and padlen) > 0 then
        begin
          padlen := padlen shl 1;

          break;
        end else padlen := padlen shr 1;
      end;
    end;


    // save old, unpadded length
    table_length := Length(ctable);
    // update new padded table length
    SetLength(ctable, padlen);
    // pad table by repeating existing characters
    for lpp0 := 0 to padlen-table_length-1 do
      ctable[table_length+lpp0] := ctable[lpp0];


    table := pstring(ctable);

    table_length := padlen; // new padded length
  end;


  nested_randomize_table();


  try
    passlen := StrToInt(ParamStr(1));
  except
    // min-max length password
    lpp0 := 1;

    temp := '';


    repeat
      temp := temp+ParamStr(1)[lpp0];

      inc(lpp0);
    until (ParamStr(1)[lpp0] = '-') or (lpp0 > Length(ParamStr(1)));


    min := StrToInt(temp);

    if min < 1 then fatal_error('Minimum length is 1.');

    inc(lpp0);

    temp := '';


    repeat
      temp := temp+ParamStr(1)[lpp0];

      inc(lpp0);
    until lpp0 > Length(ParamStr(1));


    max := StrToInt(temp);

    passlen := min + Random(max-min+1);
  end;


  password := '';

  limit    := table_length-1;


  for lpp0 := 0 to passlen-1 do
  begin
    if options[2].present then
    begin
      union := WORD_SEPARATOR;


      if lpp0 < passlen-1 then
        password := password+table[rdata[Random(maxindex)] and limit]+union
      else
        password := password+table[rdata[Random(maxindex)] and limit];
    end
  else
    begin
      password := password+table[rdata[Random(maxindex)] and limit];
    end;
  end;


  if not options[5].present then
  begin
    // write entire password at once
    WriteLn(password);
  end
    else
  begin
    // display password char by char
    for lpp0 := 0 to Length(password)-1 do
    begin
      Write(password[lpp0+1], ' --- chars left: ',Length(password)-lpp0-1);

      ReadLn();
    end;
  end;


  if not quiet then
  begin
    Write('Chars used: ');

    for lpp0 := 0 to table_length-1 do Write(table[lpp0]);

    WriteLn();
  end;
end;





begin
  randomize;

  pcount   := ParamCount();

  exe_name := ExtractFileName(ParamStr(0));

  exe_dir  := ExtractFilePath(ParamStr(0));

  work_dir := GetCurrentDir();


  if pcount < 2 then show_help();


  get_options(options);

  if options[6].present then entropy_get(ParamStr(2));

  if options[0].present then options[0].proc;

  if options[1].present then options[1].proc;

  if (options[3].present) and (options[4].present) then
    show_help();

  if (options[3].present or options[4].present) and (pcount <> 3) then
    show_help();

  if options[3].present then
  begin
    if StrToInt(ParamStr(3)) > DICT_COUNT then
      fatal_error('Dictionary ID out of range.');


    hex_to_words(ParamStr(2), dicts[StrToInt(ParamStr(3))-1])
  end
else
  if options[4].present then
  begin
    if StrToInt(ParamStr(3)) > DICT_COUNT then
      fatal_error('Dictionary ID out of range.');


    array0_count := words_to_hex_get_count(pchar(ParamStr(2)));

    SetLength(array0, array0_count);

    words_to_hex_get_words(pchar(ParamStr(2)), array0_count, array0);

    words_to_hex(array0, array0_count, dicts[StrToInt(ParamStr(3))-1]);


    halt(0);
  end;


  // get random data
  fd0 := FileOpen('/dev/urandom' , fmOpenRead);
    if fd0 < 0 then fatal_error('Could not initialize random data.');


  rdata := nil;

  rdata := GetMem(RANDOM_DATA_SIZE);
    if rdata = nil then fatal_error('Could not allocate memory.');


  if FileRead(fd0, rdata^, RANDOM_DATA_SIZE) <> RANDOM_DATA_SIZE
    then fatal_error('Could not get random data.');


  FileClose(fd0);


  case StrToInt(ParamStr(2)) of
    0: generate_password_from_table(nil, (RANDOM_DATA_SIZE div 2), 0);
    1: generate_password_from_table(@pass_table_1, (RANDOM_DATA_SIZE div 2), TABLE_1_SIZE);
    2: generate_password_from_table(@pass_table_2, (RANDOM_DATA_SIZE div 2), TABLE_2_SIZE);
    3: generate_password_from_table(@pass_table_3, (RANDOM_DATA_SIZE div 2), TABLE_3_SIZE);
    4: generate_password_from_table(@pass_table_4, (RANDOM_DATA_SIZE div 2), TABLE_4_SIZE);
    5: generate_password_from_table(@pass_table_5, (RANDOM_DATA_SIZE div 2), TABLE_5_SIZE);
    6: generate_password_from_table(@pass_table_6, (RANDOM_DATA_SIZE div 2), TABLE_6_SIZE);

    otherwise
      fatal_error('Invalid dictionary ID.');
  end;
end.
