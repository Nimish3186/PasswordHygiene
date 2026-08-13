import zxcvbn
result = zxcvbn.zxcvbn("helllllloooooo")
print(result["crack_times_display"]['offline_slow_hashing_1e4_per_second'])