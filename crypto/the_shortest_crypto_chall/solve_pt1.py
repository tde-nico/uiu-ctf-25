from tqdm import tqdm

limit = 1000
sum_map = {}

# Build all possible c^4 + d^4
for c in range(1, limit):
    for d in range(1, limit):
        s = c**4 + d**4
        sum_map[s] = (c, d)

# Now check all a^4 + b^4 and see if (a^4 + b^4 - 17) is in the map
for a in range(1, limit):
    for b in range(1, limit):
        s = a**4 + b**4
        if (s - 17) in sum_map:
            c, d = sum_map[s - 17]
            print(f"Found: a={a}, b={b}, c={c}, d={d}")
