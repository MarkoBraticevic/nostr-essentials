//
//  NIP-59GiftWrapTests.swift
//
//
//  Created by Fabian Lachman on 27/11/2025.
//

import XCTest
@testable import NostrEssentials

final class NIP_59GiftWrapTests: XCTestCase {
    
    var aliceKeys = try! Keys(privateKeyHex: "5c0c523f52a5b6fad39ed2403092df8cebc36318b39383bca6c00808626fab3a") // pubkey: 87d3561f19b74adbe8bf840682992466068830a9d8c36b4a0c99d36f826cb6cb
    
    var bobKeys = try! Keys(privateKeyHex: "4b22aa260e4acb7021e32f38a6cdf4b673c6a277755bfce287e370c924dc936d") // pubkey: fa3b4f81a620c66514bda0302847df167ed02a483141b5939e57bdd0cf76ad3b
    
    func testCreateRumor() throws {
        let keys = try Keys(privateKeyHex: "6029335db548259ab97efa5fbeea0fe21499010647a3436e83c84ff094a0670e")

        var unsignedEvent = Event(
            pubkey: "1be899d4b3479a5a3fef5fb55bf3c2d7f5aabbf81f4d13c523afa760462cd448",
            content: "Hello World", kind: 1, created_at: 1676784320
        )
        XCTAssertEqual(unsignedEvent.isRumor(), false) // missing ID so is not rumor
        
        let signedEvent = try unsignedEvent.sign(keys)
        XCTAssertEqual(try signedEvent.verified(), true) // event is signed
        XCTAssertEqual(signedEvent.isRumor(), false) // signed event can't be a rumor
        
        let rumorFromUnsignedEvent = createRumor(unsignedEvent) // makes sure ID is present and sig is removed
        XCTAssertEqual(rumorFromUnsignedEvent.isRumor(), true) // has ID and no sig
        
        let rumorFromSignedEvent = createRumor(signedEvent) // makes sure ID is present and sig is removed
        XCTAssertEqual(rumorFromSignedEvent.isRumor(), true) // has ID and no sig
    }

    func testCreateSeal() throws {
        // First create a rumor
        let unsignedEvent = Event(
            pubkey: aliceKeys.publicKeyHex,
            content: "Hello World", kind: 1, created_at: 1676784320
        )

        let rumor = createRumor(unsignedEvent) // makes sure ID is present and sig is removed
        XCTAssertEqual(rumor.isRumor(), true) // has ID and no sig
        
        // Create the seal (use bob as receiver)
        let seal = try createSignedSeal(rumor, ourKeys: aliceKeys, receiverPubkey: bobKeys.publicKeyHex)
        
        XCTAssertEqual(seal.tags.count, 0) // Make sure seal has no tags
        XCTAssertFalse(seal.content.contains("created_at")) // Make sure content is encrypted
        XCTAssertEqual(seal.kind, 13) // Should be kind 13
        XCTAssertTrue(try seal.verified())
    }
    
    func testGiftWrap() throws {
        // First create some event to wrap (can be any event, sig will be removed)
        var unsignedEvent = Event(
            pubkey: aliceKeys.publicKeyHex,
            content: "Hello World", kind: 1, created_at: 1676784320
        )
        _ = unsignedEvent.withId()

        let giftWrap = try createGiftWrap(unsignedEvent, receiverPubkey: bobKeys.publicKeyHex, keys: aliceKeys)
        
        XCTAssertEqual(giftWrap.tags.contains(where: { $0.type == "p" && $0.value == bobKeys.publicKeyHex }), true) // should have receipent p tag
        XCTAssertFalse(giftWrap.pubkey == aliceKeys.publicKeyHex) // pubkey should not be alice. should be random one-off key
        XCTAssertFalse(giftWrap.content.contains("created_at")) // Make sure content is encrypted
        XCTAssertFalse(giftWrap.content.contains(aliceKeys.publicKeyHex)) // Make alice pubkey is nowhere to be found
        XCTAssertEqual(giftWrap.kind, 1059)
        XCTAssertTrue(try giftWrap.verified())
    }
    
    func testUnwrapGift() throws {
        let giftWrap = try self.getTestGiftWrapEvent()
        XCTAssertEqual(giftWrap.kind, 1059)
        XCTAssertTrue(giftWrap.tags.contains(where: { $0.type == "p" && $0.value == bobKeys.publicKeyHex  }))
        XCTAssertTrue(giftWrap.created_at != 16767843201) // outer date should not be real date (but out of our control as receiver)


        let unwrappedGift = try unwrapGift(giftWrap, ourKeys: bobKeys)
        XCTAssertEqual(unwrappedGift.rumor.kind, 14)
        XCTAssertEqual(unwrappedGift.rumor.content, "Hello World")
        XCTAssertEqual(unwrappedGift.rumor.pubkey, aliceKeys.publicKeyHex)
        XCTAssertEqual(unwrappedGift.rumor.created_at, 1676784320)
        
        // NIP-17 in case of kind:14:
        // Clients MUST verify if pubkey of the kind:13 is the same pubkey on the kind:14, otherwise any sender can impersonate others by simply changing the pubkey on kind:14.
        if unwrappedGift.rumor.kind == 14 {
            XCTAssertEqual(unwrappedGift.rumor.pubkey, unwrappedGift.seal.pubkey)
        }
    }
    
    func testDecodeRumor() throws {
        let rumorJson = ###"{"content":"Unwrap debug test - trace the decryption failure","created_at":1771354886,"id":"ba45d6e610c2f5e05be5c4f34b98396143952ae2d8f2f16b7e925d65acf5ff6c","kind":14,"pubkey":"ffb838f52e101c8677ee2fa83982ab80669f40e04768454036ec894fba4109c1","tags":[["p","9be0be0e64d38a29a9cec9a5c8ef5d873c2bfa5362a4b558da5ff69bc3cbb81e"]]}"###
        
        guard let rumor = Event.fromJson(rumorJson) else { throw GiftWrapError.DecodeRumorError }
        
        XCTAssertEqual(rumor.kind, 14)
        XCTAssertEqual(rumor.content, "Unwrap debug test - trace the decryption failure")
        XCTAssertEqual(rumor.id, "ba45d6e610c2f5e05be5c4f34b98396143952ae2d8f2f16b7e925d65acf5ff6c")
        

    }

    private func getTestGiftWrapEvent() throws -> Event {
        var unsignedEvent = Event(
            pubkey: aliceKeys.publicKeyHex,
            content: "Hello World", kind: 14, created_at: 1676784320
        )
        _ = unsignedEvent.withId()

        return try createGiftWrap(unsignedEvent, receiverPubkey: bobKeys.publicKeyHex, keys: aliceKeys)
    }
}
