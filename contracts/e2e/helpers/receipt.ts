import type { Address } from "viem";

export function verifyReceipt(
  receipt: any,
  accountAddr: Address,
  options: {
    expectVerifyStatus?: string;
    expectSenderStatus?: string;
    expectFrameCount?: number;
    senderFrameIndex?: number;
  } = {}
) {
  const {
    expectVerifyStatus = "0x4",
    expectSenderStatus = "0x1",
    expectFrameCount = 2,
    senderFrameIndex = 1,
  } = options;

  if (receipt.status !== "0x1") {
    throw new Error(`TX failed: status=${receipt.status}`);
  }
  if (receipt.type !== "0x6") {
    throw new Error(`Wrong type: got ${receipt.type}, want 0x6`);
  }
  if (
    receipt.payer &&
    receipt.payer.toLowerCase() !== accountAddr.toLowerCase()
  ) {
    throw new Error(
      `Wrong payer: got ${receipt.payer}, want ${accountAddr}`
    );
  }
  if (receipt.frameReceipts) {
    if (receipt.frameReceipts.length !== expectFrameCount) {
      throw new Error(
        `Frame receipts count: got ${receipt.frameReceipts.length}, want ${expectFrameCount}`
      );
    }
    const verifyStatus = receipt.frameReceipts[0].status;
    if (expectVerifyStatus.includes("|")) {
      const allowed = expectVerifyStatus.split("|");
      if (!allowed.includes(verifyStatus)) {
        throw new Error(
          `VERIFY frame: got ${verifyStatus}, want one of [${allowed.join(", ")}]`
        );
      }
    } else if (verifyStatus !== expectVerifyStatus) {
      throw new Error(
        `VERIFY frame: got ${verifyStatus}, want ${expectVerifyStatus}`
      );
    }
    if (receipt.frameReceipts[senderFrameIndex].status !== expectSenderStatus) {
      throw new Error(
        `SENDER frame[${senderFrameIndex}]: got ${receipt.frameReceipts[senderFrameIndex].status}, want ${expectSenderStatus}`
      );
    }
  }
  if (BigInt(receipt.gasUsed) === 0n) {
    throw new Error("Gas used should be > 0");
  }
}
