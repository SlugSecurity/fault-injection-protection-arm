/***** Includes *****/
#include <stdio.h>
#include <stdint.h>
#include "mxc_device.h"
#include "led.h"
#include "pb.h"
#include "board.h"
#include "mxc_delay.h"

/***** Definitions *****/

/***** Globals *****/

/***** Functions *****/

// *****************************************************************************
int main(void) {

    MXC_Delay(500000);
    printf("start\n");
    printf("explicit multiplication\n");
    MXC_Delay(500000);

    long int A = 0x2BAA;

	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;
	
	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;

	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;
	
	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;
	A *= 2;

    MXC_Delay(500000);
    printf("A = %d\n", A);

    printf("mult for loop\n");
    MXC_Delay(500000);

    long int B = 0x2BAA;

    for (int i = 0; i < 5; i++) {
        B *= 2;
    }

    MXC_Delay(500000);
    printf("B = %d\n", B);

    printf("explicit addition\n");
    MXC_Delay(500000);

    long int C = 0x2BAA;
	C += 2;
	C += 2;
	C += 2;
	C += 2;
	C += 2;
	
	C += 2;
	C += 2;
	C += 2;
	C += 2;
	C += 2;

	C += 2;
	C += 2;
	C += 2;
	C += 2;
	C += 2;
	
	C += 2;
	C += 2;
	C += 2;
	C += 2;
	C += 2;

    MXC_Delay(500000);
    printf("C = %d\n", C);

    printf("add for loop\n");
    MXC_Delay(500000);

    long int D = 0x2BAA;

    for (int i = 0; i < 5; i++) {
        D += 2;
    }

    MXC_Delay(500000);
    printf("D = %d\n", D);

    printf("explicit divide\n");
    MXC_Delay(500000);

    long int E = 0x2BAA;
    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;

    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;

    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;

    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;
    E /= 2;

    MXC_Delay(500000);

    printf("E = %d\n", E);

    printf("divide for loop\n");

    MXC_Delay(500000);

    long int F = 0x2BAA;

    for (int i = 0; i < 5; i++) {
        F /= 2;
    }
    
    MXC_Delay(500000);
    printf("end\n");

    return 0;
}