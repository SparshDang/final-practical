// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "@openzeppelin/contracts/access/Ownable.sol";

contract CredentialRegistry is Ownable {



    struct Credential {
        address issuer;
        string cid;
        bool revoked;
        uint256 issuedAt;
    }

    mapping(bytes32 => Credential) public credentials;
    mapping(address => bool) public authorizedIssuers;

    event IssuerAuthorized(address indexed issuer, bool authorized);
    event CredentialIssued(bytes32 indexed didHash, address indexed issuer, string cid);
    event CredentialRevoked(bytes32 indexed didHash, address indexed revokedBy);

    constructor() {
        authorizedIssuers[msg.sender] = true;  
        emit IssuerAuthorized(msg.sender, true);
    }

    modifier onlyIssuer() {
        require(authorizedIssuers[msg.sender], "Not an authorized issuer");
        _;
    }

    function setAuthorizedIssuer(address issuer, bool allowed) external onlyOwner {
        authorizedIssuers[issuer] = allowed;
        emit IssuerAuthorized(issuer, allowed);
    }

    function issueCredential(bytes32 didHash, string calldata cid) external onlyIssuer {
        require(credentials[didHash].issuedAt == 0, "Credential exists");
        
        credentials[didHash] = Credential({
            issuer: msg.sender,
            cid: cid,
            revoked: false,
            issuedAt: block.timestamp
        });

        emit CredentialIssued(didHash, msg.sender, cid);
    }

    function getCredential(bytes32 didHash)
        external
        view
        returns (
            bool exists,
            address issuer,
            string memory cid,
            bool revoked,
            uint256 issuedAt
        )
    {
        Credential memory c = credentials[didHash];
        if (c.issuedAt == 0) return (false, address(0), "", false, 0);
        return (true, c.issuer, c.cid, c.revoked, c.issuedAt);
    }

    function revokeCredential(bytes32 didHash) external {
        Credential storage c = credentials[didHash];
        require(c.issuedAt != 0, "Not found");
        require(msg.sender == c.issuer || msg.sender == owner(), "Not authorized");
        require(!c.revoked, "Already revoked");
        
        c.revoked = true;

        emit CredentialRevoked(didHash, msg.sender);
    }
}
