
int
memcmp(a, b, len)
	char *a;
	char *b;
	int len;
{
	int n = 0;
	
	while (n < len) {
		if (a[n] != b[n])
		   return a[n] - b[n];
		n++;
	}
	return 0;
}
