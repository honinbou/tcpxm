/***************************************************************************
 * 
 * Copyright (c) 2012 Baidu.com, Inc. All Rights Reserved
 * $Id$ 
 * 
**************************************************************************/
 
/**
 * @file test_hello.c
 * @author guowei(dpf-rd@baidu.com)
 * @date 2012/11/10 21:52:18
 * @version $Revision$ 
 * @brief 
 *  
 **/

#include <stdio.h>
#include <stdlib.h>

#include "queue.h"

struct bufferq {
	/* The length of buf. */
	int data;
	/* For the linked list structure. */
	TAILQ_ENTRY(bufferq) entries;
};

TAILQ_HEAD(, bufferq) bufq;

int main(int argc, char const *argv[])
{
	TAILQ_INIT(&bufq);
	for (int i = 0; i < 10; ++i)
	{
		struct bufferq *inputq;
		inputq = (bufferq* )calloc(1, sizeof(bufferq));
		inputq->data = i;
		
		TAILQ_INSERT_TAIL(&bufq, inputq, entries);
	}

	struct bufferq *tmp;
	tmp = TAILQ_FIRST(&bufq);
	int count = 0;
	while(tmp != NULL)
	{
		count++;
		tmp = TAILQ_NEXT(tmp, entries);
	}
	printf("size: %d\n", count);

	for (int i = 0; i < 10; ++i)
	{
		struct bufferq *outputq;
		outputq = TAILQ_FIRST(&bufq);
		int data = outputq->data;
		printf("output: %d\n", data);

		TAILQ_REMOVE(&bufq, outputq, entries);
		free(outputq);
	}
}