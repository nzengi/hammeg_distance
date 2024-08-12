import os
import ecdsa
import hashlib
import base58
import random
import multiprocessing

# SHA256 ve RIPEMD160 hash fonksiyonları
def sha256(data):
    return hashlib.sha256(data).digest()

def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()

# Public key'den Bitcoin adresi oluşturma
def pubkey_to_address(pubkey):
    sha256_bpk = sha256(pubkey)
    ripemd160_bpk = ripemd160(sha256_bpk)
    hashed_pubkey = b'\x00' + ripemd160_bpk
    checksum = sha256(sha256(hashed_pubkey))[:4]
    binary_address = hashed_pubkey + checksum
    address = base58.b58encode(binary_address).decode('utf-8')
    return address

# Özel anahtarı compressed Bitcoin adresine dönüştürme
def private_key_to_compressed_address(private_key):
    sk = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    public_key = b'\x02' + vk.to_string()[:32] if vk.to_string()[32] % 2 == 0 else b'\x03' + vk.to_string()[:32]
    return pubkey_to_address(public_key)

# Hamming Mesafesi Hesaplama Fonksiyonu (binary formatta)
def hamming_distance(s1, s2):
    b1 = bin(int.from_bytes(s1.encode(), 'big'))[2:].zfill(160)
    b2 = bin(int.from_bytes(s2.encode(), 'big'))[2:].zfill(160)
    return sum(c1 != c2 for c1, c2 in zip(b1, b2))

# Diferansiyel Evrim Fonksiyonları
def generate_initial_population(pop_size, start_range, end_range):
    return [random.randint(start_range, end_range) for _ in range(pop_size)]

def fitness_function(private_key_int, target_address):
    private_key = private_key_int.to_bytes(32, 'big')
    address = private_key_to_compressed_address(private_key)
    return hamming_distance(address, target_address)

def mutation(population, F, start_range, end_range):
    new_population = []
    for i in range(len(population)):
        x1, x2, x3 = random.sample(population, 3)
        mutant = x1 + int(F * (x2 - x3))
        if mutant < start_range or mutant > end_range:
            mutant = random.randint(start_range, end_range)
        new_population.append(mutant)
    return new_population

def crossover(target, mutant, CR):
    return mutant if random.random() < CR else target

def worker(target_address, start_range, end_range, pop_size, generations, F, CR):
    return adaptive_differential_evolution(target_address, start_range, end_range, pop_size, generations, F, CR)

def adaptive_differential_evolution(target_address, start_range, end_range, pop_size=2000, generations=100000000, F=0.5, CR=0.7):
    print(f"Starting Differential Evolution: pop_size={pop_size}, generations={generations}")
    population = generate_initial_population(pop_size, start_range, end_range)
    
    for generation in range(generations):
        new_population = []
        for i in range(pop_size):
            mutant = mutation(population, F, start_range, end_range)[i]
            trial = crossover(population[i], mutant, CR)
            if fitness_function(trial, target_address) < fitness_function(population[i], target_address):
                new_population.append(trial)
            else:
                new_population.append(population[i])
        
        population = new_population
        fitnesses = [fitness_function(ind, target_address) for ind in population]
        best_fit = min(fitnesses)
        if generation % 100 == 0:
            print(f"Generation {generation}: Best Hamming Distance = {best_fit}")  # Nesil ve Hamming Mesafesi Yazdırma

        # Uyarlanabilir adımlar
        if generation % 100 == 0:  # Her 100 nesilde bir parametreleri ayarlayın
            if best_fit < 50:
                F = max(0.1, F - 0.05)
                CR = min(0.9, CR + 0.05)
            elif best_fit > 100:
                F = min(0.9, F + 0.05)
                CR = max(0.1, CR - 0.05)

        if best_fit == 0:
            print("Exact match found!")  # Tam Eşleşme Bulunduğunda Yazdırma
            break
    
    best_key = population[fitnesses.index(min(fitnesses))]
    print(f"Best private key (hex): {best_key.to_bytes(32, 'big').hex()} with Hamming Distance = {best_fit}")  # En İyi Sonuç Yazdırma
    return best_key

# Paralel Hesaplama
def parallel_differential_evolution(target_address, start_hex, end_hex, num_processes=4):
    start_range = int(start_hex, 16)
    end_range = int(end_hex, 16)
    
    # Aralığı işlemler arasında bölüştür
    step = (end_range - start_range) // num_processes
    ranges = [(start_range + i*step, start_range + (i+1)*step) for i in range(num_processes)]
    
    with multiprocessing.Pool(num_processes) as pool:
        results = pool.starmap(worker, [(target_address, r[0], r[1], 2000, 100000000, 0.5, 0.7) for r in ranges])
    
    return results

# Kullanım örneği
if __name__ == "__main__":
    print("Starting parallel differential evolution...")
    target_address = "13zb1hQbWVsc2S7ZTZnP2G4undNNpdh5so"  # Hedef Bitcoin adresi
    
    # Hex stringleri integer'a çevir
    start_hex = '0000000000000000000000000000000000000000000000030000000000000000'
    end_hex = '000000000000000000000000000000000000000000000003ffffffffffffffff'

    # Paralel Diferansiyel Evrim
    results = parallel_differential_evolution(target_address, start_hex, end_hex, num_processes=4)
    print("Parallel differential evolution completed.")
