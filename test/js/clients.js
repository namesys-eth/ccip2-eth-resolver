import { createWalletClient, createTestClient, createPublicClient, http } from 'viem'
import { goerli } from 'viem/chains'

const transport = http("http://127.0.0.1:8545")

export const anvil = createTestClient({
  chain: goerli,
  mode: 'anvil',
  transport: transport
})

export const wallet = createWalletClient({
  chain: goerli,
  transport: transport
})

export const client = createPublicClient({
    chain: goerli,
    transport: transport
})