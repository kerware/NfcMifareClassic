package fr.supavenir.lsts.nfcmifareclassic;

import androidx.appcompat.app.AppCompatActivity;

import android.app.PendingIntent;
import android.bluetooth.BluetoothAdapter;
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
                    Toast.LENGTH_SHORT);
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
        switch( action ) {
            case NfcAdapter.ACTION_TAG_DISCOVERED :
                Tag tag = (Tag) intent.getParcelableExtra( NfcAdapter.EXTRA_TAG);
                String techniques = "Techniques possibles :";
                String[] strTech = tag.getTechList();
                for( String t : strTech ) {
                    techniques += "\n"+t;
                }
                techniques += "\nId du tag " + tag.getId();
                MifareClassic mifare = MifareClassic.get( tag );
                techniques +="\nNb blocs : " + mifare.getBlockCount();
                techniques +="\nNb secteurs : " + mifare.getSectorCount();
                techniques +="\nTaille en octets : " + mifare.getSize();
                int nbBlockSector1 = mifare.getBlockCountInSector(1);
                techniques +="\nNb blocs dans secteur 1 : " + nbBlockSector1;
                int sectorForBlock33 = mifare.blockToSector( 33 );
                techniques +="\nSecteur du bloc 33 : " + sectorForBlock33;

                // ECRITURE SUR LE BLOC N°4 (Secteur 1 )
                try {
                    writeMessageWithMifareClassic( tag , "SMB116" , 4 );
                } catch( IOException e ) {

                }

                // RECUPERATION DU CONTENU DU BLOC N° 4 (secteur 1)
                try {
                    String payload = readPayloadFromBlockWithMifareClassic(
                            tag , 4 );
                    techniques += "\nPayload bloc n°4 : " + payload;
                } catch (IOException e) {
                    e.printStackTrace();
                }
                tvTagTechList.setText( techniques );
                break;
        }
    }

    // ATTENTION UN BLOC CONTIENT 16 caracteres maxi
    private void writeMessageWithMifareClassic( Tag tag , String payload ,
                                                int block ) throws IOException {
        MifareClassic mifare = MifareClassic.get(tag);
        byte[] defaultKeys = MifareClassic.KEY_DEFAULT;
        mifare.connect();
        boolean auth = mifare.authenticateSectorWithKeyA(
                mifare.blockToSector(block), defaultKeys);
        if (auth) {
            byte[] payloadInBytes = payload.getBytes(StandardCharsets.US_ASCII);
            payloadInBytes = Arrays.copyOf( payloadInBytes , 16 );
            mifare.writeBlock( block , payloadInBytes);
        }
        mifare.close();
    }
    private String readPayloadFromBlockWithMifareClassic( Tag tag ,
                                                 int block ) throws IOException {
        MifareClassic mifare = MifareClassic.get( tag );
        byte[] payload = {};
        byte[] defaultKeys = MifareClassic.KEY_DEFAULT;
        mifare.connect();
        boolean auth = mifare.authenticateSectorWithKeyA(
                mifare.blockToSector( block ) , defaultKeys);
        if ( auth ) {
            payload = mifare.readBlock( block );
        }
        mifare.close();
        return new String( payload , StandardCharsets.US_ASCII );
    }

}