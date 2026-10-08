// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
import {SkillRegistry} from "../src/SkillRegistry.sol";
import {SkillLicense} from "../src/SkillLicense.sol";

contract ArbitrationTest is Test {
    SkillRegistry registry;
    SkillLicense license;
    address publisher=address(11);
    address auditor=address(12);
    address arbiter=address(13);
    address treasury=address(14);
    bytes32 report=bytes32(uint256(77));
    function setUp() public {
        registry=new SkillRegistry(address(this));
        license=new SkillLicense(address(this));
        registry.setSkillLicense(address(license));license.setRegistry(address(registry));
        registry.configureArbitration(arbiter,treasury);
        vm.deal(publisher,10 ether);vm.deal(auditor,10 ether);
        vm.prank(auditor);registry.stakeAsAuditor{value:0.01 ether}();
        vm.prank(publisher);registry.register("test","1","source",bytes32(uint256(1)),bytes32(uint256(2)));
        vm.prank(publisher);registry.requestAudit{value:0.01 ether}("test","1");
    }
    function freeze() internal {vm.prank(auditor);registry.submitReport("test","1",true,report);}
    function testMaliciousReportFreezesDepositAndDoesNotRewardAuditor() public {
        uint256 beforeBalance=auditor.balance;freeze();
        (,,,,uint256 deposit,SkillRegistry.Status state,,)=registry.skills(registry.keyOf("test","1"));
        assertEq(uint256(state),5);assertEq(deposit,0.01 ether);assertEq(auditor.balance,beforeBalance);assertEq(license.totalMinted(),0);
        (address reporter,bytes32 original,uint256 openedAt,uint256 deadline,bytes32 finalHash)=registry.arbitrations(registry.keyOf("test","1"));
        assertEq(reporter,auditor);assertEq(original,report);assertEq(openedAt,block.timestamp);assertEq(deadline,block.timestamp+7 days);assertEq(finalHash,bytes32(0));
    }
    function testConfigurationIsOnceAndRolesSeparated() public {
        vm.expectRevert();registry.configureArbitration(address(20),address(21));
        vm.expectRevert();registry.transferOwnership(arbiter);
        vm.expectRevert();registry.transferOwnership(treasury);
        registry.transferOwnership(address(30));assertEq(registry.owner(),address(30));
    }
    function testUnconfiguredCannotRequestAudit() public {
        SkillRegistry r=new SkillRegistry(address(this));
        vm.prank(publisher);r.register("a","1","source",report,report);
        vm.prank(publisher);vm.expectRevert();r.requestAudit{value:0.01 ether}("a","1");
    }
    function testProtectedWalletCannotStake() public {
        vm.deal(arbiter,1 ether);vm.prank(arbiter);vm.expectRevert();registry.stakeAsAuditor{value:0.01 ether}();
    }
    function testInvalidConfiguration() public {
        SkillRegistry r=new SkillRegistry(address(this));
        vm.expectRevert();r.configureArbitration(address(0),treasury);
        vm.expectRevert();r.configureArbitration(arbiter,arbiter);
        vm.expectRevert();r.configureArbitration(address(this),treasury);
    }
    function testDuplicateReportRejected() public {freeze();vm.prank(auditor);vm.expectRevert();registry.submitReport("test","1",true,report);}

    function resolve(bool malicious) internal {
        vm.prank(arbiter);registry.resolveArbitration("test","1",malicious,bytes32(uint256(88)));
    }
    function testConfirmedMaliciousCreditsOnlyTreasury() public {
        freeze();resolve(true);
        assertEq(uint256(registry.getStatus("test","1")),4);
        assertEq(registry.credits(treasury),0.01 ether);assertEq(registry.credits(auditor),0);
        assertEq(license.totalMinted(),0);
        vm.prank(treasury);registry.withdrawFunds();assertEq(treasury.balance,0.01 ether);
        vm.prank(treasury);vm.expectRevert();registry.withdrawFunds();
        vm.prank(arbiter);vm.expectRevert();registry.resolveArbitration("test","1",true,report);
    }
    function testOverturnCreditsPublisherAndMints() public {
        freeze();resolve(false);
        assertEq(uint256(registry.getStatus("test","1")),3);assertEq(registry.credits(publisher),0.01 ether);
        assertEq(license.totalMinted(),1);
        (,,,,uint256 deposit,,bytes32 hash,address reporter)=registry.skills(registry.keyOf("test","1"));
        assertEq(deposit,0);assertEq(hash,bytes32(uint256(88)));assertEq(reporter,auditor);
        assertEq(address(registry).balance,0.02 ether);
    }
    function testTimeoutCreditsPublisherWithoutLicense() public {
        freeze();vm.warp(block.timestamp+7 days);
        vm.prank(arbiter);vm.expectRevert();registry.resolveArbitration("test","1",false,report);
        vm.prank(address(99));registry.expireArbitration("test","1");
        assertEq(uint256(registry.getStatus("test","1")),6);assertEq(registry.credits(publisher),0.01 ether);assertEq(license.totalMinted(),0);
        vm.expectRevert();registry.expireArbitration("test","1");
    }
    function testDeadlineBoundaryAndWrongArbiter() public {
        freeze();vm.expectRevert();registry.resolveArbitration("test","1",true,report);
        vm.prank(arbiter);vm.expectRevert();registry.resolveArbitration("test","1",true,bytes32(0));
        vm.expectRevert();registry.expireArbitration("test","1");
        vm.warp(block.timestamp+7 days-1);resolve(true);
    }
    function testSafeReportCreditsPublisher() public {
        uint256 beforeBalance=publisher.balance;
        vm.prank(auditor);registry.submitReport("test","1",false,report);
        assertEq(publisher.balance,beforeBalance);assertEq(registry.credits(publisher),0.01 ether);
        vm.prank(publisher);registry.withdrawFunds();assertEq(publisher.balance,beforeBalance+0.01 ether);
    }
    function testFuzzFundsConservation(uint96 rawDeposit) public {
        uint256 amount=bound(uint256(rawDeposit),0.01 ether,5 ether);
        vm.prank(publisher);registry.register("extra","1","source",report,report);
        vm.prank(publisher);registry.requestAudit{value:amount}("extra","1");
        vm.prank(auditor);registry.submitReport("extra","1",true,report);
        vm.prank(arbiter);registry.resolveArbitration("extra","1",true,report);
        assertEq(address(registry).balance,registry.auditorStake(auditor)+0.01 ether+registry.credits(treasury));
        vm.prank(treasury);registry.withdrawFunds();assertEq(address(registry).balance,0.02 ether);
    }
    function testRejectingAndReentrantRecipient() public {
        WithdrawalReceiver receiver=new WithdrawalReceiver();
        registry=new SkillRegistry(address(this));registry.configureArbitration(arbiter,address(receiver));
        vm.prank(auditor);registry.stakeAsAuditor{value:0.01 ether}();
        vm.prank(publisher);registry.register("test","1","source",report,report);
        vm.prank(publisher);registry.requestAudit{value:0.01 ether}("test","1");
        freeze();resolve(true);assertEq(registry.credits(address(receiver)),0.01 ether);
        vm.expectRevert();receiver.withdraw(registry);assertEq(registry.credits(address(receiver)),0.01 ether);
        receiver.accept();receiver.withdraw(registry);
        assertEq(address(receiver).balance,0.01 ether);assertFalse(receiver.reentered());assertEq(registry.credits(address(receiver)),0);
    }
}
contract WithdrawalReceiver {
    bool public rejecting=true;
    bool public reentered;
    SkillRegistry registry;
    function accept() external {rejecting=false;}
    function withdraw(SkillRegistry r) external {registry=r;r.withdrawFunds();}
    receive() external payable {
        require(!rejecting);
        try registry.withdrawFunds(){reentered=true;}catch{}
    }
}
