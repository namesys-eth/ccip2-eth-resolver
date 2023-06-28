import { createWalletClient, createTestClient, createPublicClient, http } from 'viem'
import { goerli } from 'viem/chains'
import 'dotenv/config'

export const RPC_URL = process.env.LOCAL_RPC_URL;

const transport = http(RPC_URL)

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