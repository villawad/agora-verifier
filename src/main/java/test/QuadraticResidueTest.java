package test;

import verificatum.protocol.mixnet.*;

import java.io.*;
import java.util.*;

import verificatum.*;
import verificatum.arithm.*;
import verificatum.crypto.*;
import verificatum.eio.*;
import verificatum.ui.*;
import verificatum.ui.info.*;
import verificatum.ui.opt.*;
import verificatum.ui.tui.*;
import verificatum.util.*;
import verificatum.protocol.*;
import verificatum.protocol.coinflip.*;
import verificatum.protocol.hvzk.*;
import verificatum.protocol.distrkeygen.*;

/*
To fix in Verificatum:

implement a method in LargeIntegerArrayIM or LargeIntegerArray

public LargeIntegerArray extractQuadraticResidues() {

        final List<LargeInteger> results =
            Collections.synchronizedList(new LinkedList<LargeInteger>());

        ArrayWorker worker =
            new ArrayWorker(li.length) {
                public void work(int start, int end) {

                    for (int i = start; i < end; i++) {
                        if (li[i].legendre(prime) != 1) {
                            // results.add(Boolean.FALSE);
                            // break;
                            // warning
                        } else {
                            results.add(li[i]);
                        }
                    }
                    // results.add(Boolean.TRUE);

                }
            };
        worker.work();


        return new LargeIntegerArrayIM(results.toArray());
    }


*/

public class QuadraticResidueTest {

    public static void test(String ctexts) throws Exception {
        String privateInfoFilename = "privInfo.xml";

        String protocolInfoFilename = "protInfo.xml";

        // Read private info and protocol info.
        InfoGenerator generator = new MixNetElGamalGen();
        PrivateInfo privateInfo = generator.newPrivateInfo();
        ProtocolInfo protocolInfo = generator.newProtocolInfo();

        privateInfo.parse(privateInfoFilename);
        protocolInfo.parse(protocolInfoFilename);


        UI ui = new TextualUI(new TConsole());
        Protocol rootProtocol =
                    new Protocol(privateInfo, protocolInfo, ui);


        String pGroupString = protocolInfo.getStringValue("pgroup");
        PGroup pGroup =
        Marshalizer.unmarshalHexAux_PGroup(pGroupString,
            rootProtocol.randomSource,
            rootProtocol.certainty);
        int width = protocolInfo.getIntValue("width");
        ElGamalReencShuffle shuffle =
                new ElGamalReencShuffleStandard(pGroup, width);


        // Import ciphertexts.
        System.out.println("reading from " + ctexts);
        File ciphFile = new File(ctexts);
        PPGroupElementArray ciphertexts = null;

        PPGroup ppGroup = (PPGroup) shuffle.getEncryptor(1).getArrayRange();

        // MixNetElGamalInterfaceRawTest mixnetInterface = new MixNetElGamalInterfaceRawTest();
        // ciphertexts = (PPGroupElementArray) mixnetInterface.readCiphertexts(shuffle.getEncryptor(1).getArrayRange(), ciphFile);

        ModPGroup oneP = (ModPGroup) ppGroup.project(0);
        ModPGroup twoP = (ModPGroup) ppGroup.project(1);

        LargeInteger modulusOne = oneP.getModulus();
        LargeInteger modulusTwo = oneP.getModulus();

        ByteTreeBasic bt = new ByteTreeF(ciphFile);
        ByteTreeReader btr = bt.getByteTreeReader();

        LargeIntegerArrayIM laOne = (LargeIntegerArrayIM) LargeIntegerArray.toLargeIntegerArray(0, btr.getNextChild(), LargeInteger.ONE, modulusOne);

        LargeIntegerArrayIM laTwo = (LargeIntegerArrayIM) LargeIntegerArray.toLargeIntegerArray(0, btr.getNextChild(), LargeInteger.ONE, modulusTwo);

        List<Boolean> retOne = quadraticResidues(laOne.integers(), modulusOne);
        List<Boolean> retTwo = quadraticResidues(laTwo.integers(), modulusTwo);

        for(int i = 0; i < retOne.size(); i++) {
            if(!retOne.get(i).booleanValue()) {
                System.out.println("* invalid: " + i);
            }
        }

        for(int i = 0; i < retTwo.size(); i++) {
            if(!retTwo.get(i).booleanValue()) {
                System.out.println("* invalid: " + i);
            }
        }
        /* boolean okOne = laOne.quadraticResidues(modulusOne);
        boolean okTwo = laTwo.quadraticResidues(modulusTwo);

        System.out.println(okOne + " " + okTwo);*/

        /* System.out.println(ciphertexts.getClass());
        ModPGroupElementArray one = (ModPGroupElementArray) ciphertexts.project(0);
        ModPGroupElementArray two = (ModPGroupElementArray) ciphertexts.project(1);
        LargeInteger modulusOne = ((ModPGroup)one.getPGroup()).getModulus();
        LargeInteger modulusTwo = ((ModPGroup)two.getPGroup()).getModulus();

        System.out.println(one.values.quadraticResidues(modulusOne));
        System.out.println(two.values.quadraticResidues(modulusTwo));*/
        // System.out.println(two.getClass());

    }

    public static List<Boolean> quadraticResidues(final LargeInteger[] integers, final LargeInteger prime) {
        final List<Boolean> results = Collections.synchronizedList(new LinkedList<Boolean>());

        ArrayWorker worker =
            new ArrayWorker(integers.length) {
                public void work(int start, int end) {

                    for (int i = start; i < end; i++) {
                        if (integers[i].legendre(prime) != 1) {
                            results.add(Boolean.FALSE);
                            break;
                        }
                    }
                    results.add(Boolean.TRUE);
                }
            };
        worker.work();

        return results;
    }
}