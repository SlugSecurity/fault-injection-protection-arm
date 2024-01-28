/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include "mxc_device.h"
#include "led.h"
#include "pb.h"
#include "board.h"
#include "mxc_delay.h"

/***** Definitions *****/
#define LED 0 // LED to flash.  We default to '0', since LED driver definitions may vary across micros.

/***** Globals *****/

/***** Functions *****/

// *****************************************************************************
int main(void) {
    int userPassword;

    LED_On(LED1);
    MXC_Delay(500000);
    printf("Hello World!\n");
    printf("Enter password:\n");


    while (1) {
        scanf("%d", &userPassword);

        if (userPassword == 6) {
            printf("Password correct.\n");
            MXC_Delay(500000);
            LED_Off(LED1);
            MXC_Delay(500000);
            break;
        } else {
            printf("Try again.\n");
        }
    }

    return 0;
}
