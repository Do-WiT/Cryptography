import java.io.*;
import java.util.Base64;

public class Utilities {

    public static  String enBase64(byte[] bytes){
        return Base64.getEncoder().encodeToString(bytes);
    }
    public static byte[] deBase64(String base64){
        return Base64.getDecoder().decode(base64);
    }
    public static byte[] serialize(Object obj) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream os = new ObjectOutputStream(out);
        os.writeObject(obj);
        return out.toByteArray();
    }
    public static Object deserialize(byte[] data) throws IOException, ClassNotFoundException {
        ByteArrayInputStream in = new ByteArrayInputStream(data);
        ObjectInputStream is = new ObjectInputStream(in);
        return is.readObject();
    }
}
