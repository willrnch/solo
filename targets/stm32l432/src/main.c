// Copyright 2019 SoloKeys Developers
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#include "sha3.h"
#include "uECC.h"
#include "cbor.h"
#include "flash.h"
#include "device.h"
#include "memory_layout.h"
#include "util.h"
#include "log.h"

#include APP_CONFIG

#include "usbd_hid.h"

#if !defined(TEST)


#define PUBLIC_KEY_SIZE 64
#define PRIVATE_KEY_SIZE 32
#define ETH_ADDR_SIZE 20

#define KEY_PER_PAGE (FLASH_PAGE_SIZE / PRIVATE_KEY_SIZE)

#define RES_KEY_CREATED 0x1
#define RES_DUMP_KEYS 0x2
#define RES_SIGN 0x3
#define RES_DONE 0xFF

static void dumpbytes(const uint8_t *buf, size_t len)
{
  uint8_t *str = malloc(len * 2);
  if (buf == NULL) {
    printf1(TAG_DUMP2, "MALLOC ERROR\n");
  } else {
    size_t i = 0;
    while (i < len) {
      sprintf(str + (i * 2), "%02x", buf[i]);
      ++i;
    }
    printf1(TAG_DUMP2, "0x%*s", len * 2, str);
    free(str);
  }
}

static int check_index(uint8_t index) {
  if (index >= KEY_PER_PAGE) {
    return 1;
  }
  return 0;
}

void public_key_to_eth_address(uint8_t *key, uint8_t *address) {
  sha3_context c;
  sha3_Init256(&c);
  sha3_SetFlags(&c, SHA3_FLAGS_KECCAK);
  sha3_Update(&c, key, PUBLIC_KEY_SIZE);
  const uint8_t *hash = sha3_Finalize(&c);
  memmove(address, hash + 12, ETH_ADDR_SIZE);
}

uint8_t * get_private_key(uint8_t index) {
  uint8_t * privkey = ((uint8_t *) flash_addr(STATE1_PAGE)) + (index * PRIVATE_KEY_SIZE);
  return privkey;
}

int write_private_key(uint8_t index, uint8_t * key) {
  uint8_t page_cpy[FLASH_PAGE_SIZE];
  uint8_t * page_ptr = (uint8_t *) flash_addr(STATE1_PAGE);

  printf1(TAG_DUMP2, "write_private_key %d %p %p\n", index, page_cpy, page_cpy + (index * PRIVATE_KEY_SIZE));

  memcpy(page_cpy, page_ptr, FLASH_PAGE_SIZE);
  memcpy(page_cpy + (index * PRIVATE_KEY_SIZE), key, PRIVATE_KEY_SIZE);

  flash_erase_page(STATE1_PAGE);
  flash_write(
      (uint32_t) page_ptr,
      page_cpy,
      FLASH_PAGE_SIZE
  );

  return 0;
}

int create_key_pair(uint8_t index, uint8_t * address) {
  uint8_t pubkey[PUBLIC_KEY_SIZE];
  uint8_t privkey[PRIVATE_KEY_SIZE];
  const struct uECC_Curve_t * curve = uECC_secp256k1();

  int code = uECC_make_key(pubkey, privkey, curve);
  if (code != 1) {
    printf2(TAG_ERR, "Error, uECC_make_key failed. code = %d\n", code);
    return -1;
  }

  if (write_private_key(index, privkey) != 0) {
    return -1;
  }

  public_key_to_eth_address(pubkey, address);
  return 0;
}

int is_private_key_null(uint8_t *addr) {
  uint8_t i;

  for (i = 0; i < PRIVATE_KEY_SIZE; ++i) {
    if (addr[i] != 0) {
      return 0;
    }
  }
  return 1;
}

void private_key_to_eth_addr(uint8_t *privkey, uint8_t *addr) {
  uint8_t pubkey[PUBLIC_KEY_SIZE];
  const struct uECC_Curve_t * curve = uECC_secp256k1();

  uECC_compute_public_key(privkey, pubkey, curve);
  public_key_to_eth_address(pubkey, addr);
}

int key_to_eth_addr(uint8_t index, uint8_t *addr) {
  uint8_t * privkey = get_private_key(index);

  if (is_private_key_null(privkey)) {
    return -1;
  }
  private_key_to_eth_addr(privkey, addr);
  return 0;
}

void cmd_hello(uint8_t * hid_msg) {
  printf1(TAG_DUMP2, "%s\n", __func__);

  printf1(TAG_DUMP2, "hello\n");
}

void cmd_reset(uint8_t * hid_msg) {
  printf1(TAG_DUMP2, "%s\n", __func__);

  uint8_t buff[FLASH_PAGE_SIZE];
  uint8_t * page_ptr = (uint8_t *) flash_addr(STATE1_PAGE);

  memset(buff, 0, FLASH_PAGE_SIZE);
  flash_erase_page(STATE1_PAGE);
  flash_write(
      (uint32_t) page_ptr,
      buff,
      FLASH_PAGE_SIZE
  );
}

int sign(uint8_t *privkey, uint8_t *buf, uint8_t length, uint8_t *sig) {
  const struct uECC_Curve_t * curve = uECC_secp256k1();
  if (!uECC_sign(privkey, buf, length, sig, curve)) {
    return -1;
  }
  return 0;
}

void cmd_sign(uint8_t * hid_msg) {
  uint8_t index = hid_msg[1];
  if (check_index(index)) {
    return;
  }

  uint8_t signature[64];
  uint8_t *mess = hid_msg + 2;
  uint8_t mess_len = 32;

  uint8_t *private_key = get_private_key(index);

  if (is_private_key_null(private_key)) {
    return;
  }

  uint8_t addr[ETH_ADDR_SIZE];
  private_key_to_eth_addr(private_key, addr);

  printf1(TAG_DUMP2, "addr =\n");
  dumpbytes(addr, ETH_ADDR_SIZE);
  printf1(TAG_DUMP2, "\n");

  if (sign(private_key, mess, mess_len, signature) == 0) {
    uint8_t res[HID_PACKET_SIZE];

    printf1(TAG_DUMP2, "signature: \n");
    dumpbytes(signature, 64);
    printf1(TAG_DUMP2, "\n");

    res[0] = RES_SIGN;
    memcpy(res + 1, signature, 32);
    usbhid_send(res);

    memcpy(res + 1, signature + 32, 32);
    usbhid_send(res);
  }
}

void cmd_delete_key(uint8_t * hid_msg) {
  uint8_t index = hid_msg[1];
  if (check_index(index)) {
    return;
  }

  uint8_t privkey[PRIVATE_KEY_SIZE];
  memset(privkey, 0, PRIVATE_KEY_SIZE);
  write_private_key(index, privkey);
}

void cmd_create_key(uint8_t * hid_msg) {
  printf1(TAG_DUMP2, "%s\n", __func__);

  uint8_t index = hid_msg[1];
  uint8_t eth_addr[ETH_ADDR_SIZE];

  if (check_index(index)) {
    return;
  }

  create_key_pair(index, eth_addr);

  printf1(TAG_DUMP2, "cmd_create_key: ");
  dump_hex1(TAG_DUMP2, eth_addr, ETH_ADDR_SIZE);
  printf1(TAG_DUMP2, "\n");

  uint8_t res[HID_PACKET_SIZE];
  memset(res, 0, HID_PACKET_SIZE);
  memcpy(res + 1, eth_addr, ETH_ADDR_SIZE);
  res[0] = RES_KEY_CREATED;
  usbhid_send(res);
}

void cmd_dump_keys(uint8_t * hid_msg) {
  printf1(TAG_DUMP2, "%s\n", __func__);

  uint8_t res[HID_PACKET_SIZE];
  uint8_t key_slot_size = ETH_ADDR_SIZE + 1; // index + addr
  uint8_t key_per_msg = (HID_PACKET_SIZE - 1) / (key_slot_size);
  int i;
  int j = 0;
  uint8_t eth_addr[ETH_ADDR_SIZE];

  memset(res, 0xFF, HID_PACKET_SIZE);
  res[0] = RES_DUMP_KEYS;

  for (i = 0; i < KEY_PER_PAGE; ++i) {
    if (key_to_eth_addr(i, eth_addr) == 0) {
      res[1 + (j * key_slot_size)] = i;
      memcpy((res + 1) + (j * key_slot_size) + 1, eth_addr, ETH_ADDR_SIZE);

      j += 1;

      if (j >= key_per_msg) {
        usbhid_send(res);
        memset(res, 0xFF, HID_PACKET_SIZE);
        res[0] = RES_DUMP_KEYS;
        j = 0;
      }
    }
  }

  if (j > 0) {
    usbhid_send(res);
  }
}

struct {
  uint8_t op_code;
  void (*handler)(uint8_t *);
} commands[] = {
  { 0x0, &cmd_hello },
  { 0x1, &cmd_reset },
  { 0x2, &cmd_create_key },
  { 0x3, &cmd_dump_keys },
  { 0x4, &cmd_delete_key },
  { 0x5, &cmd_sign },
  { 0x0, NULL },
};

int main(int argc, char *argv[])
{
  uint8_t hidmsg[64];
  uint32_t t1 = 0;
  uint8_t i;

  set_logging_mask(
      /*0*/
      //TAG_GEN|
      // TAG_MC |
      // TAG_GA |
      TAG_WALLET |
      TAG_STOR |
      //TAG_NFC_APDU |
      TAG_NFC |
      //TAG_CP |
      // TAG_CTAP|
      //TAG_HID|
      TAG_U2F|
      //TAG_PARSE |
      TAG_TIME|
      TAG_DUMP|
      TAG_DUMP2|
      TAG_GREEN|
      TAG_RED|
      TAG_EXT|
      TAG_CCID|
      TAG_ERR
      );

  device_init(argc, argv);

  memset(hidmsg, 0, sizeof(hidmsg));

  while (1) {
    if (millis() - t1 > HEARTBEAT_PERIOD) {
      heartbeat();
      t1 = millis();
    }

    device_manage();

    uint8_t r = usbhid_recv(hidmsg);

    if (r > 0) {
      // printf1(TAG_DUMP2, ">> ");
      // dump_hex1(TAG_DUMP2, hidmsg, sizeof(hidmsg));
      // printf1(TAG_DUMP2, "\n");

      for (i = 0; commands[i].handler != NULL; ++i) {
        if (hidmsg[0] == commands[i].op_code) {
          commands[i].handler(hidmsg);

          uint8_t res[HID_PACKET_SIZE];
          memset(res, 0, HID_PACKET_SIZE);
          res[0] = RES_DONE;
          usbhid_send(res);

          break;
        }
      }

      memset(hidmsg, 0, sizeof(hidmsg));
    }
  }

  // Should never get here
  usbhid_close();
  printf1(TAG_GREEN, "done\n");
  return 0;
}

#endif
