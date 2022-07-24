<?php

namespace KmsEncryption;

use Aws\Kms\Exception\KmsException;
use Aws\Kms\KmsClient;
use Closure;
use Illuminate\Foundation\Application;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Str;
use KmsEncryption\Console\Commands\KmsGenerateDataKey;
use KmsEncryption\Console\Commands\KmsTest;

class KmsEncryptionServiceProvider extends ServiceProvider
{
    public function register()
    {
        // register client
        $this->app->bind(KmsClient::class, function(Application $app, $params = []) {
            print_r([
                'version' => '2014-11-01',
                'region' => config('aws.region') ?? $params['region'] ?? env('AWS_DEFAULT_REGION'),
                'credentials' => [
                   'key'    => config('aws.credentials.key') ?? $params['credentials']['key'] ?? env('AWS_ACCESS_KEY_ID') ?? null,
                   'secret' => config('aws.credentials.secret') ?? $params['credentials']['secret'] ?? env('AWS_SECRET_ACCESS_KEY') ?? null,
                ],
            ]);
            return new KmsClient([
                'version' => '2014-11-01',
                'region' => config('aws.region') ?? $params['region'] ?? env('AWS_DEFAULT_REGION'),
                'credentials' => [
                   'key'    => config('aws.credentials.key') ?? $params['credentials']['key'] ?? env('AWS_ACCESS_KEY_ID') ?? null,
                   'secret' => config('aws.credentials.secret') ?? $params['credentials']['secret'] ?? env('AWS_SECRET_ACCESS_KEY') ?? null,
                ],
            ]);

        });

        // register commands
        if ($this->app->runningInConsole()) {
            $this->commands([
                KmsGenerateDataKey::class,
                KmsTest::class,
            ]);
        }
    }

    public function boot()
    {
        // skip if no cmk configured
        if(!env('AWS_KMS_CMK')){
            return;
        }

        // grab the (kms) encrypted APP_KEY
        $key = config('app.key');

        if (Str::startsWith($key, $prefix = 'base64:')) {
            $key = base64_decode(Str::after($key, $prefix));
        }

        try {

            // instantiate the kms client with default settings
            /** @var KmsClient $client */
            $client = $this->app->make(KmsClient::class);

            // try to decrypt the key using kms
            $decrypted = $client->decrypt([
                'CiphertextBlob' => $key,
                'KeyId' => env('AWS_KMS_CMK'),
            ])->get('Plaintext');

        } catch (KmsException $kmsException){
            throw new \Exception($kmsException->getMessage());
        }

        $encoded = 'base64:' . base64_encode($decrypted);

        // override app key with decrypted key
        Config::set('app.key', $encoded);
    }
}
