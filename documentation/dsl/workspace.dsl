workspace "PKI con Uso de Certificados x509 para autenticar usuarios en servidores" {
    model {
        user = person "Usuario final"
        userHost = softwareSystem "Host de usuario"
        group "Infraestructura servidores" {
            bastion = softwareSystem "Bastion" "Proxy de autenticacion a la red interna."
            ejbca = softwareSystem "EJBCA" "Autoridad de certificacion, registro y validacion."
            destino1 = softwareSystem "Servidor destino 1" "Ejemplo de servidor destino."
            auth_server = softwareSystem "Servidor de autenticacion" "Servidor de autenticacion de usuarios." {
                container "Servicio de autenticacion" {
                    technology "Python Fast Api"
                    component "Validacion de certificado" {
                        technology "Python"
                    }
                }
            }

            user -> userHost "solicita acceso a destino1 a través de bastion" "SSH with proxy tunnel"
            bastion -> auth_server "Valida que certificado no este expirado ni revocado" "REST HTTPS"
            auth_server -> ejbca "Pregunta estado de revocacion de un certificado" "REST HTTPS"
            auth_server -> ejbca "Busca el certificado completo" "REST HTTPS"
            userHost -> bastion "Solicitud de conexion" "SSH command"
            bastion -> destino1 "Redirije solicitud de conexion" "SSH"
            destino1 -> auth_server "Valida que certificado no este expirado ni revocado" "REST HTTPS"
        }
    }

    views {
        systemLandscape Company {
            include *
            autoLayout lr
        }
        container auth_server {
            include *
            autoLayout lr
        }

        theme default
    }
}