import { normalize, namehash } from 'viem/ens'

export function dnsEncode(domain) {
    const _domain = normalize(domain)
    const _labels = _domain.split(".")
    let _encoded = "0x"
    for (let i = 0; i < _labels.length; i++) {
        _encoded += (_labels[i].length).toString(16).padStart(2, "0")
        _encoded += Array.from(
            utf8Encoder.encode(_labels[i]),
            b => b.toString(16).padStart(2, "0")
        ).join("")
    }
    return _encoded += "00"
}
