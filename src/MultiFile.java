import java.io.Serializable;
import java.util.Arrays;

public class MultiFile implements Serializable {

    private String fileName;
    private byte[] content;

    public MultiFile(String fileName, byte[] content) {
        this.fileName = fileName;
        this.content = content;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public byte[] getContent() {
        return content;
    }

    public void setContent(byte[] content) {
        this.content = content;
    }

    @Override
    public String toString() {
        return "MultiFile{" +
                "fileName='" + fileName + '\'' +
                ", content=" + Arrays.toString(content) +
                '}';
    }
}
