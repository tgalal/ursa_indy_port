import hashlib
import math

def calc_teq(p_pub_key:dict,
             a_prime:int,
             e:int,
             v:int,
             m_tilde:dict,
             m2tilde:int,
             unrevealed_attrs:list):

    result = pow(a_prime, e, p_pub_key['n'])

    for k in unrevealed_attrs:
        k = k.lower()
        cur_r = p_pub_key['r'][k]
        cur_m = m_tilde[k]
        result = (pow(cur_r, cur_m, p_pub_key['n']) * result) % p_pub_key['n']

    result = (pow(p_pub_key['s'], v, p_pub_key['n']) * result) % p_pub_key['n']
    result = (pow(p_pub_key['rctxt'], m2tilde, p_pub_key['n']) * result) % p_pub_key['n']

    return result

def calc_tne(
    p_pub_key: dict,
    u: dict[str, int], # ne_proof.u
    r: dict[str, int], # ne_proof.r
    mj: int,
    alpha: int,
    t: dict[str, int],
    is_less: bool
):
    tau_list: list[int] = []

    for i in range(0, 4):
        cur_u = u[str(i)]
        cur_r = r[str(i)]
        t_tau = (
                pow(p_pub_key['z'], cur_u, p_pub_key['n'])
                * 
                pow(p_pub_key['s'], cur_r, p_pub_key['n'])
            ) % p_pub_key['n']
        tau_list.append(t_tau)
	
    delta: int = r['DELTA']
    delta_predicate = -delta if is_less else delta

    t_tau = (
            pow(p_pub_key['z'], mj, p_pub_key['n'])
            * 
            pow(p_pub_key['s'], delta_predicate, p_pub_key['n'])
        ) % p_pub_key['n']

    tau_list.append(t_tau)

    q = 1

    for i in range(0, 4):
        cur_t = t[str(i)]
        cur_u = u[str(i)]
        q = (pow(cur_t, cur_u, p_pub_key['n']) * q) % p_pub_key['n']

    q = (pow(p_pub_key['s'], alpha, p_pub_key['n']) * q) % p_pub_key['n']

    tau_list.append(q);

    return tau_list

def predicate_is_less(predicate:dict) -> bool:
    return predicate['p_type'].upper() in ('LE', 'LT')

def predicate_get_delta_prime(predicate:dict) -> bool:
    p_type = predicate['p_type']
    if p_type == 'GT':
        return predicate['value'] + 1
    if p_type == 'LT':
        return predicate['value'] - 1

    return predicate['value']

######################################################

def verify_equality(p_pub_key:dict,
                    proof:dict,
                    c_hash:int,
                    cred_schema: dict,
                    non_cred_schema: dict,
                    sub_proof_request: dict) -> list[int]:
    # Get set of unrevealed attribute names by comparing the set of
    # requested attributes to the set of all attributes
    all_attrs = set(cred_schema['attrs'] + non_cred_schema['attrs'])
    revealed_attrs = set(sub_proof_request['revealed_attrs'])

    unrevealed_attrs = list(all_attrs - revealed_attrs)
    
    t1 = calc_teq(
            p_pub_key=p_pub_key,
            a_prime=proof['a_prime'],
            e=proof['e'],
            v=proof['v'],
            m_tilde=proof['m'],
            m2tilde=proof['m2'],
            unrevealed_attrs=unrevealed_attrs
            )
    rar = pow(proof['a_prime'], 2**596, p_pub_key['n'])

    for attr, encoded_value in proof['revealed_attrs'].items():
        cur_r = p_pub_key['r'][attr]
        rar = (pow(cur_r, encoded_value, p_pub_key['n']) * rar) % p_pub_key['n']

    z_inverted = pow(p_pub_key['z'], -1, p_pub_key['n'])
    t2 = pow(z_inverted * rar, c_hash, p_pub_key['n'])

    t = (t1 * t2) % p_pub_key['n']

    return [t]

def verify_ne_predicate(
    p_pub_key: dict, # credential_primary_public_key
    proof: dict, # ne_proof
    c_hash: int
) -> list[int]:
    tau_list = calc_tne(
            p_pub_key,
            proof['u'],
            proof['r'],
            proof['mj'],
            proof['alpha'],
            proof['t'],
            predicate_is_less(proof['predicate'])
            )
    for i in range(0, 4):
        cur_t = proof['t'][str(i)]
        # TODO optimization: can we do pow(x, -c_hash, y)?
        cur_t_inverse = pow(cur_t, -1, p_pub_key['n'])
        tau_list[i] = (pow(cur_t_inverse, c_hash, p_pub_key['n']) * tau_list[i]) % p_pub_key['n']

    delta = proof['t']['DELTA']
    if predicate_is_less(proof['predicate']):
        delta_prime = pow(delta, -1, p_pub_key['n'])
    else:
        delta_prime = delta

    tau_delta_intermediate = pow(p_pub_key['z'], predicate_get_delta_prime(proof['predicate']), p_pub_key['n'])
    tau_delta_intermediate = (tau_delta_intermediate * delta_prime) % p_pub_key['n']
    tau_delta_intermediate = pow(tau_delta_intermediate, c_hash, p_pub_key['n'])
    tau_delta_intermediate = pow(tau_delta_intermediate, -1, p_pub_key['n'])

    # Compute $\widehat{T_\delta}$
    tau_list[4] = (tau_delta_intermediate * tau_list[4]) % p_pub_key['n']

    tau_5_intermediate = pow(delta, c_hash, p_pub_key['n'])
    tau_5_intermediate = pow(tau_5_intermediate, -1, p_pub_key['n'])

    # Compute $\widehat{Q}$
    tau_list[5] = (tau_5_intermediate * tau_list[5]) % p_pub_key['n']

    return tau_list

def verify_primary_proof(p_pub_key:dict,
                    c_hash:int,
                    primary_proof:dict,
                    cred_schema: dict,
                    non_cred_schema: dict,
                    sub_proof_request: dict) -> list[int]:

    t_hat = verify_equality(
        p_pub_key,
        primary_proof['eq_proof'],
        c_hash,
        cred_schema,
        non_cred_schema,
        sub_proof_request
    )

    for ne_proof in primary_proof['ge_proofs']:
        t_hat.extend(verify_ne_predicate(p_pub_key, ne_proof, c_hash))

    return t_hat

def verify_non_revocation_proof():
    return []

def verify(proof:dict,
        nonce: int,
        p_pub_key:dict,
        cred_schema: dict,
        non_cred_schema: dict,
        sub_proof_request: dict
        ):
    c_hash = int(proof['aggregated_proof']['c_hash'])
    c_list = proof['aggregated_proof']['c_list']
    tau_list = []

    for proof_item in proof['proofs']:
        primary_proof = proof_item['primary_proof']

        tau_list.extend(verify_non_revocation_proof())
        tau_list.extend(verify_primary_proof(p_pub_key = p_pub_key,
            c_hash=c_hash,
            primary_proof=primary_proof,
            cred_schema=cred_schema,
            non_cred_schema=non_cred_schema,
            sub_proof_request=sub_proof_request
        ))

    final_hash = hashlib.sha256()
    for item in tau_list:
        num_bytes = math.ceil(item.bit_length() / 8.0)
        final_hash.update(item.to_bytes(num_bytes, 'big'))
    for item in c_list:
        final_hash.update(bytearray(item))

    final_hash.update(nonce.to_bytes(10, 'big'))
    final_hash_result = int.from_bytes(final_hash.digest(), 'big')

    return final_hash_result == c_hash
