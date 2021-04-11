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

            return new KmsClient([
                'profile' => $params['profile'] ?? env('AWS_ROLE'),
                'version' => '2014-11-01',
                'region' => $params['region'] ?? env('AWS_DEFAULT_REGION'),
                'credentials' => [
                    'key'    => $params['region']['my-access-key-id'] ?? env('AWS_ACCESS_KEY_ID') ?? null,
                    'secret' => $params['region']['my-secret-access-key'] ?? env('AWS_SECRET_ACCESS_KEY') ?? null,
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

        }catch (KmsException $kmsException){
            return;
        }

        $encoded = 'base64:' . base64_encode($decrypted);

        // override app key with decrypted key
        Config::set('app.key', $encoded);
    }
}