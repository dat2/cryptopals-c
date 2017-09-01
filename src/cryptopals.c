#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "byte_string.h"
#include "set1.h"

static void challenge1() {
  char* expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
  char* actual = NULL;

  byte_string* byte_string = from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
  actual = to_base64(byte_string);

  printf("challenge 1:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free_byte_string(&byte_string);
  free(actual);
}

static void challenge2() {
  char* expected = "746865206b696420646f6e277420706c6179";
  char* actual = NULL;

  byte_string* a = from_hex("1c0111001f010100061a024b53535009181c");
  byte_string* b = from_hex("686974207468652062756c6c277320657965");
  byte_string* c = fixed_xor(a, b);
  actual = to_hex(c);

  printf("challenge 2:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(&a);
  free_byte_string(&b);
  free_byte_string(&c);
}

static void challenge3() {
  char* expected = "Cooking MC's like a pound of bacon";
  char* actual = NULL;

  byte_string* unknown = from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");

  byte decryption_char;
  byte_string* decoded = decrypt_fixed_xor(unknown, &decryption_char);
  actual = to_ascii(decoded);

  printf("challenge 3:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("decryption char: %c\n", decryption_char);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(&unknown);
  free_byte_string(&decoded);
}

static void challenge4() {
  char* file_name = "data/4.txt";
  char* expected = "Now that the party is jumping\\n";
  char* actual = NULL;

  size_t n_byte_strings;
  byte_string** byte_strings = read_lines_hex(file_name, &n_byte_strings);

  byte_string* decoded = detect_single_character_xor(byte_strings, n_byte_strings);
  actual = to_ascii(decoded);

  printf("challenge 4:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(&decoded);
  for(size_t i = 0; i < n_byte_strings; i++) {
    free_byte_string(&byte_strings[i]);
  }
}

static void challenge5() {
  char* expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
  char* actual = NULL;

  byte_string* input = from_ascii("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal");
  byte_string* key = from_ascii("ICE");
  byte_string* out = encrypt_repeating_key_xor(input, key);
  actual = to_hex(out);

  printf("challenge 5:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free_byte_string(&input);
  free_byte_string(&key);
  free_byte_string(&out);
  free(actual);
}

static void challenge6() {
  char* expected = "I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \nn";
  char* actual = NULL;

  byte_string* input = read_file_base64("data/6.txt");
  byte_string* out = break_repeating_key_xor(input);
  actual = to_ascii(out);

  printf("challenge 6:\n");
  printf("expected: %s\n", expected);
  printf("actual  : %s\n", actual);
  printf("expected == actual: %s\n", strcmp(expected, actual) == 0 ? "true" : "false");

  free(actual);
  free_byte_string(&input);
  free_byte_string(&out);
}

int main(int argc, char** argv) {
  setlocale(LC_ALL, "");

  challenge1();
  printf("\n");
  challenge2();
  printf("\n");
  challenge3();
  printf("\n");
  challenge4();
  printf("\n");
  challenge5();
  printf("\n");
  challenge6();

  return 0;
}
