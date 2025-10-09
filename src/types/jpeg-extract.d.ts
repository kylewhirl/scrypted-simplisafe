declare module 'jpeg-extract' {
    import { RequestOptions } from 'https';

    interface ExtractOptions extends RequestOptions {
        url?: string;
    }

    function jpegExtract(options: ExtractOptions | string): Promise<Buffer>;

    export default jpegExtract;
}
