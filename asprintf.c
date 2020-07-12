// SPDX-License-Identifier: BSD-2-Clause
/*
 * asprintf - a short implementation of asprintf based on Ben Klemens paper
 *	      https://modelingwithdata.org/pdfs/174-asprintf.pdf
 *
 * Copyright (c) 2014, Ben Klemens
 * Copyright (c) 2020, Rafael Aquini <aquini@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  1. Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *
 *  2. Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS
 *  BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

int asprintf(char **str, char *fmt, ...)
{
	int len;
	char buf[1];
	va_list argp;

	va_start(argp, fmt);
	len = vsnprintf(buf, 1, fmt, argp);
	va_end(argp);
	if (len < 1) {
		*str = NULL;
		goto out;
	}

	if ((*str = malloc(len + 1)) == NULL) {
		len = -1;
		goto out;
	}

	va_start(argp, fmt);
	len = vsnprintf(*str, len + 1, fmt, argp);
	va_end(argp);
out:
	return len;
}
