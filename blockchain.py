"""
blockchain.py
-------------
"""
"""
SecureVote Blockchain Ledger

A deliberately simple, dependency-free, hash-linked blockchain
used to record votes.

Each vote is stored as a Block. Every block contains:
- index
- timestamp
- vote data
- previous block hash
- its own SHA-256 hash

Changing the contents of an existing block changes its hash and
breaks the hash links with the following blocks.

This is a local blockchain-style ledger for a student project.
It is NOT a decentralized blockchain because it does not include
peer-to-peer networking, consensus, mining, validators, or
multiple independent nodes.
"""

import hashlib
import json
import os
import threading
import time


class Block:
    """
    Represents one block in the blockchain.
    """

    def __init__(self, index, timestamp, data, previous_hash, hash_=None):
        self.index = index
        self.timestamp = timestamp
        self.data = data
        self.previous_hash = previous_hash

        # Use the existing hash when loading a block.
        # Calculate a new hash when creating a new block.
        self.hash = hash_ or self.compute_hash()

    def compute_hash(self):
        """
        Calculate the SHA-256 hash of the block's contents.

        The hash depends on:
        - index
        - timestamp
        - data
        - previous_hash
        """

        payload = json.dumps(
            {
                "index": self.index,
                "timestamp": self.timestamp,
                "data": self.data,
                "previous_hash": self.previous_hash,
            },
            sort_keys=True,
        )

        return hashlib.sha256(
            payload.encode("utf-8")
        ).hexdigest()

    def to_dict(self):
        """
        Convert the Block object into a dictionary
        so it can be stored in JSON.
        """

        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "data": self.data,
            "previous_hash": self.previous_hash,
            "hash": self.hash,
        }


class Blockchain:
    """
    Manages the complete blockchain and JSON persistence.
    """

    def __init__(self, chain_file="chain_data.json"):
        self.chain_file = chain_file
        self.chain = []
        self._lock = threading.RLock()

        self._load_or_init()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load_or_init(self):
        """
        Load the blockchain from the JSON file.

        If the file does not exist, create a genesis block.
        If an existing file is corrupt, fail closed instead of
        silently replacing evidence with a new ledger.
        """

        if os.path.exists(self.chain_file):
            try:
                with open(self.chain_file, "r", encoding="utf-8") as f:
                    raw_blocks = json.load(f)

                if not isinstance(raw_blocks, list):
                    raise ValueError(
                        "Blockchain JSON must contain a list."
                    )

                loaded_chain = []

                for block_data in raw_blocks:
                    required_fields = {
                        "index",
                        "timestamp",
                        "data",
                        "previous_hash",
                        "hash",
                    }

                    if not required_fields.issubset(block_data.keys()):
                        raise ValueError(
                            "Blockchain contains a block with missing fields."
                        )

                    block = Block(
                        index=block_data["index"],
                        timestamp=block_data["timestamp"],
                        data=block_data["data"],
                        previous_hash=block_data["previous_hash"],
                        hash_=block_data["hash"],
                    )

                    loaded_chain.append(block)

                if not loaded_chain:
                    raise ValueError(
                        "Blockchain file cannot be empty."
                    )

                self.chain = loaded_chain

                chain_valid, message = self.is_valid()

                if not chain_valid:
                    raise ValueError(message)

                return

            except (
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
                OSError,
            ) as exc:
                raise RuntimeError(
                    "Existing blockchain ledger is invalid. "
                    "Restore a known-good backup before starting."
                ) from exc

        # Create the first block if no usable blockchain exists.
        genesis = Block(
            index=0,
            timestamp=time.time(),
            data={"info": "Genesis Block"},
            previous_hash="0",
        )

        self.chain = [genesis]
        self._save()

    def _save(self):
        """
        Save the complete blockchain to chain_data.json.
        """

        with self._lock:
            directory = os.path.dirname(self.chain_file)

            if directory:
                os.makedirs(directory, exist_ok=True)

            temporary_file = f"{self.chain_file}.tmp"

            with open(
                temporary_file,
                "w",
                encoding="utf-8",
            ) as file:
                json.dump(
                    [
                        block.to_dict()
                        for block in self.chain
                    ],
                    file,
                    indent=2,
                )
                file.flush()
                os.fsync(file.fileno())

            os.replace(
                temporary_file,
                self.chain_file,
            )

    # ------------------------------------------------------------------
    # Core blockchain operations
    # ------------------------------------------------------------------

    def last_block(self):
        """
        Return the most recent block.
        """

        with self._lock:
            return self.chain[-1]

    def add_block(self, data):
        """
        Create and add a new block to the blockchain.
        """

        with self._lock:
            previous_block = self.last_block()

            new_block = Block(
                index=previous_block.index + 1,
                timestamp=time.time(),
                data=data,
                previous_hash=previous_block.hash,
            )

            self.chain.append(new_block)

            self._save()

            return new_block

    def is_valid(self):
        """
        Check the integrity of the entire blockchain.

        Checks:
        1. Genesis block is valid.
        2. Each block points to the correct previous block.
        3. Each block's stored hash matches its calculated hash.
        4. Block indexes are sequential.

        Returns:
            (True, "Chain is valid")
        or:
            (False, reason)
        """

        with self._lock:
            if not self.chain:
                return False, "Blockchain is empty"

        # --------------------------------------------------------------
        # Check the Genesis Block
        # --------------------------------------------------------------

            genesis = self.chain[0]

            if genesis.index != 0:
                return False, "Genesis block must have index 0"

            if genesis.previous_hash != "0":
                return False, "Genesis block has an invalid previous_hash"

            if genesis.hash != genesis.compute_hash():
                return False, "Genesis block has been altered"

        # --------------------------------------------------------------
        # Check every block after Genesis
        # --------------------------------------------------------------

            for i in range(1, len(self.chain)):
                current_block = self.chain[i]
                previous_block = self.chain[i - 1]

            # Check previous hash link
                if current_block.previous_hash != previous_block.hash:
                    return (
                        False,
                        f"Block {current_block.index} previous_hash "
                        f"does not match block {previous_block.index}",
                    )

            # Recalculate current block hash
                recalculated_hash = current_block.compute_hash()

                if current_block.hash != recalculated_hash:
                    return (
                        False,
                        f"Block {current_block.index} has been altered "
                        f"(hash mismatch)",
                    )

            # Check block numbering
                if current_block.index != previous_block.index + 1:
                    return (
                        False,
                        f"Invalid block index sequence between "
                        f"block {previous_block.index} and "
                        f"block {current_block.index}",
                    )

            return True, "Chain is valid"

    def all_vote_blocks(self):
        """
        Return all blocks except the Genesis Block.

        Block 0 = Genesis Block
        Block 1 onwards = Vote blocks
        """

        with self._lock:
            return [
                block
                for block in self.chain
                if block.index != 0
            ]
