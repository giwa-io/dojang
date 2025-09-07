// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Emitted when the indexer is updated
event IndexerUpdated(address indexed prevIndexer, address indexed newIndexer);

/// @notice Emitted when the schema book is updated
event SchemaBookUpdated(address indexed prevBook, address indexed newBook);

/// @notice Emitted when the dojang attester book is updated
event DojangAttesterBookUpdated(address indexed prevBook, address indexed newBook);

/// @notice Emitted when zero address is given
error ZeroAddress();

/// @notice Thrown when trying to set invalid indexer
error InvalidIndexer();

/// @notice Thrown when trying to set invalid schema book
error InvalidSchemaBook();

/// @notice Thrown when trying to set invalid dojang attester book
error InvalidDojangAttesterBook();
