/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include "mxc_device.h"
#include "led.h"
#include "pb.h"
#include "board.h"
#include "mxc_delay.h"
#include "gpio.h"

#define GPIO_PORT_OUT MXC_GPIO2
#define GPIO_PIN_OUT MXC_GPIO_PIN_0

#define BUFLEN 64

uint8_t memory[BUFLEN];
uint8_t tmp[BUFLEN];
char asciibuf[BUFLEN];
uint8_t pt[16];

void my_puts(const char *c) {
    UART_Write(MXC_UART_GET_UART(CONSOLE_UART), (uint8_t *)c, strlen(c));
}

void my_read(char *buf, int len) {
    int numBytes = 0;
    for (int i = 0; i < len; i++) {
        numBytes = UART_Read(MXC_UART_GET_UART(CONSOLE_UART), (uint8_t*)&buf[i], 1);
        if (buf[i] == '\n' || numBytes <= 0) {
            buf[i] = '\0';
            break;
        }
    }
}

void gpio_setup() {
    mxc_gpio_cfg_t gpio_out;
    gpio_out.port = GPIO_PORT_OUT;
    gpio_out.mask = GPIO_PIN_OUT;
    gpio_out.pad = MXC_GPIO_PAD_NONE;
    gpio_out.func = MXC_GPIO_FUNC_OUT;
    gpio_out.vssel = MXC_GPIO_VSSEL_VDDIOH;
    MXC_GPIO_Config(&gpio_out);
}

void gpio_set_state(int state) {
    if (state) {
        MXC_GPIO_OutSet(GPIO_PORT_OUT, GPIO_PIN_OUT);
    } else {
        MXC_GPIO_OutClr(GPIO_PORT_OUT, GPIO_PIN_OUT);
    }
}

int main(void) {
    Console_Init();
    gpio_setup();

    char passwd[32];
    char correct_passwd[] = "h0px3";

    while (1) {
        my_puts("*****Safe-o-matic 3000 Booting...\n");
        MXC_TMR_Delay(MXC_TMR0, MSEC(2000)); // 2-second delay

        my_puts("Please enter password to continue: ");
        my_read(passwd, sizeof(passwd));

        uint8_t passbad = 0;

        for (uint8_t i = 0; i < strlen(correct_passwd); i++) {
            if (correct_passwd[i] != passwd[i]) {
                passbad = 1;
                break;
            }
        }

        if (passbad) {
            my_puts("PASSWORD FAIL\n");
            gpio_set_state(0); // Set GPIO low for incorrect password
            LED_Toggle(LED_RED);
        } else {
            my_puts("Access granted, Welcome!\n");
            gpio_set_state(1); // Set GPIO high for correct password
            LED_Toggle(LED_GREEN);
        }

        // Infinite loop to halt execution, a reset is required to retry
        while (1) {
            MXC_TMR_Delay(MXC_TMR0, MSEC(1000)); // 1-second delay to indicate the loop is active
        }
    }

    return 1;
}
