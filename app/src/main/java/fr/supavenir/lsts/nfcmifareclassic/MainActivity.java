package fr.supavenir.lsts.nfcmifareclassic;

import androidx.appcompat.app.AppCompatActivity;

import android.app.PendingIntent;
import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.MifareClassic;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class MainActivity extends AppCompatActivity {
    // L'adaptateur NFC
    private NfcAdapter nfcAdapter;
    // L'intention en attente d'une detection NFC
    private PendingIntent nfcPendingIntent;


    private TextView tvTagTechList;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        tvTagTechList = findViewById( R.id.tvTagTechList );


        nfcAdapter = NfcAdapter.getDefaultAdapter( this );
        if ( nfcAdapter == null ) {
            // Pas d'adaptateur NFC
            Toast.makeText( this, "Pas de fonction NFC",
                    Toast.LENGTH_SHORT).show();
            finish();
        }

        // Création du PendingIntent
        nfcPendingIntent = PendingIntent.getActivity( this, 0,
                new Intent( this, this.getClass()).addFlags(
                        Intent.FLAG_ACTIVITY_SINGLE_TOP ) , 0);
    }

    @Override
    protected void onResume() {
        super.onResume();
        if ( nfcAdapter != null ) {
            nfcAdapter.enableForegroundDispatch( this , nfcPendingIntent, null , null);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if ( nfcAdapter != null ) {
            nfcAdapter.disableForegroundDispatch( this );
        }
    }

    @Override
    protected void onNewIntent( Intent intent ) {
        super.onNewIntent( intent );
        setIntent( intent );
        treatIntent( intent );
    }

    private void treatIntent( Intent intent ) {
        String action = intent.getAction();
        if (action == null) return;

        switch( action ) {
            case NfcAdapter.ACTION_TAG_DISCOVERED :
            case NfcAdapter.ACTION_TECH_DISCOVERED:
                Tag tag = intent.getParcelableExtra( NfcAdapter.EXTRA_TAG);
                if (tag == null) return;

                String techniques = "Techniques possibles :";
                String[] strTech = tag.getTechList();
                for( String t : strTech ) {
                    techniques += "\n"+t;
                }
                techniques += "\nId du tag " + bytesToHexString(tag.getId());
                MifareClassic mifare = MifareClassic.get( tag );
                if (mifare != null) {
                    techniques +="\nNb blocs : " + mifare.getBlockCount();
                    techniques +="\nNb secteurs : " + mifare.getSectorCount();
                    techniques +="\nTaille en octets : " + mifare.getSize();
                    int nbBlockSector1 = mifare.getBlockCountInSector(1);
                    techniques +="\nNb blocs dans secteur 1 : " + nbBlockSector1;
                    int sectorForBlock33 = mifare.blockToSector( 33 );
                    techniques +="\nSecteur du bloc 33 : " + sectorForBlock33;
                }

                // ECRITURE DU MESSAGE SUR LES DIFFERENTS BLOCS (Secteur 1 )
                try {
                    // On commence au bloc 4 (début du secteur 1)
                    writeLongMessageWithMifareClassic( tag , "SMB116 du CNAM PARIS, www.cnam.fr", 4 );
                    // Bloc 4 : SMB116 du CNAM P
                    // Bloc 5 : ARIS, www.cnam.f
                    // Bloc 6 : r
                } catch( IOException e ) {
                        Toast.makeText( this, "Erreur en écriture", Toast.LENGTH_LONG).show();
                }

                // RECUPERATION DU CONTENU DU BLOC N° 2 (secteur 1) -> Bloc 5
                try {
                    String payload = readPayloadFromBlockWithMifareClassic(
                            tag , 5 );
                    techniques += "\nPayload bloc n°5 : " + payload;
                } catch (IOException e) {
                    e.printStackTrace();
                }
                tvTagTechList.setText( techniques );
                break;
        }
    }

    private String bytesToHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }

    /**
     * Découpe le payload en blocs de 16 caractères et les écrit à partir d'un bloc de départ.
     */
    private void writeLongMessageWithMifareClassic(Tag tag, String payload, int startBlock) throws IOException {
        final int TAILLE_BLOCK = 16;
        for (int i = 0; i < payload.length(); i += TAILLE_BLOCK) {
            int end = Math.min(i + TAILLE_BLOCK, payload.length());
            String chunk = payload.substring(i, end);
            writeMessageWithMifareClassic(tag, chunk, startBlock + (i / TAILLE_BLOCK));
        }
    }

    // ATTENTION UN BLOC CONTIENT 16 caracteres maxi
    private void writeMessageWithMifareClassic( Tag tag , String payload ,
                                                int block ) throws IOException {
        MifareClassic mifare = MifareClassic.get(tag);
        if (mifare == null) return;
        byte[] defaultKeys = MifareClassic.KEY_DEFAULT;
        mifare.connect();
        try {
            boolean auth = mifare.authenticateSectorWithKeyA(
                    mifare.blockToSector(block), defaultKeys);
            if (auth) {
                byte[] payloadInBytes = payload.getBytes(StandardCharsets.US_ASCII);
                payloadInBytes = Arrays.copyOf( payloadInBytes , 16 );
                mifare.writeBlock( block , payloadInBytes);
            }
        } finally {
            mifare.close();
        }
    }

    private String readPayloadFromBlockWithMifareClassic( Tag tag ,
                                                 int block ) throws IOException {
        MifareClassic mifare = MifareClassic.get( tag );
        if (mifare == null) return "";
        byte[] payload = {};
        byte[] defaultKeys = MifareClassic.KEY_DEFAULT;
        mifare.connect();
        try {
            boolean auth = mifare.authenticateSectorWithKeyA(
                    mifare.blockToSector( block ) , defaultKeys);
            if ( auth ) {
                payload = mifare.readBlock( block );
            }
        } finally {
            mifare.close();
        }
        return new String( payload , StandardCharsets.US_ASCII );
    }

}
